"""Content-free delivery evidence; acceptance alone never confirms delivery.

State aggregates are monotonic: complaint > bounced > rejected > delivered > awaiting.
The priority preserves adverse evidence under duplicate and out-of-order notifications.
No ledger operation sends mail or changes the existing outbound operation journal.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from _thread import RLock
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Any


class DeliveryStatus(StrEnum):
    AWAITING = "awaiting"
    DELIVERED = "delivered"
    REJECTED = "rejected"
    BOUNCED = "bounced"
    COMPLAINT = "complaint"


_PRIORITY = {status: index for index, status in enumerate(DeliveryStatus)}
_OPERATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def _identifier(value: object, name: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value or len(value) > 998:
        raise ValueError(f"invalid {name}")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"invalid {name}")
    return value


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamp requires a timezone")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class DeliveryEvent:
    event_id: str
    provider: str
    grant_id: str
    status: DeliveryStatus
    occurred_at: datetime
    operation_id: str | None = None
    provider_message_id: str | None = None
    rfc_message_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("event_id", "provider", "grant_id"):
            _identifier(getattr(self, name), name)
        for name in ("operation_id", "provider_message_id", "rfc_message_id"):
            _identifier(getattr(self, name), name, optional=True)
        if self.operation_id and not _OPERATION.fullmatch(self.operation_id):
            raise ValueError("invalid operation_id")
        if not any((self.operation_id, self.provider_message_id, self.rfc_message_id)):
            raise ValueError("delivery event lacks correlation identifiers")
        if not isinstance(self.status, DeliveryStatus) or self.status is DeliveryStatus.AWAITING:
            raise ValueError("delivery event requires terminal evidence")
        _utc(self.occurred_at)

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result.update(version=1, occurred_at=_utc(self.occurred_at).isoformat())
        return result

    @classmethod
    def from_dict(cls, value: object) -> DeliveryEvent:
        names = {
            "version",
            "event_id",
            "provider",
            "grant_id",
            "status",
            "occurred_at",
            "operation_id",
            "provider_message_id",
            "rfc_message_id",
        }
        if (
            not isinstance(value, dict)
            or set(value) - names
            or type(value.get("version")) is not int
            or value.get("version") != 1
        ):
            raise ValueError("invalid normalized delivery event")
        timestamp = value.get("occurred_at")
        if not isinstance(timestamp, str):
            raise ValueError("invalid occurred_at")
        return cls(
            event_id=str(_identifier(value.get("event_id"), "event_id")),
            provider=str(_identifier(value.get("provider"), "provider")),
            grant_id=str(_identifier(value.get("grant_id"), "grant_id")),
            status=DeliveryStatus(str(_identifier(value.get("status"), "status"))),
            occurred_at=datetime.fromisoformat(timestamp.replace("Z", "+00:00")),
            operation_id=_identifier(value.get("operation_id"), "operation_id", optional=True),
            provider_message_id=_identifier(
                value.get("provider_message_id"), "provider_message_id", optional=True
            ),
            rfc_message_id=_identifier(
                value.get("rfc_message_id"), "rfc_message_id", optional=True
            ),
        )


@dataclass(frozen=True, slots=True)
class DeliveryRecord:
    provider: str
    operation_id: str
    grant_id: str
    provider_message_id: str | None
    rfc_message_id: str | None
    status: DeliveryStatus
    accepted_at: datetime
    updated_at: datetime
    last_event_at: datetime | None


@dataclass(frozen=True, slots=True)
class EventResult:
    disposition: str
    duplicate: bool
    operation_id: str | None


class DeliveryStore:
    """An additive ledger in the bridge database, without a schema version bump.

    Pass an existing connection for in-memory MappingStore integration. Otherwise
    use the same database path; independent SQLite connections serialize writes.
    """

    def __init__(
        self,
        path: str | Path = ":memory:",
        *,
        connection: sqlite3.Connection | None = None,
        lock: RLock | None = None,
    ) -> None:
        self._owns_connection = connection is None
        self._lock = lock or threading.RLock()
        if connection is None:
            resolved = str(Path(path).expanduser()) if str(path) != ":memory:" else ":memory:"
            if resolved != ":memory:":
                target = Path(resolved)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if not target.exists():
                    try:
                        descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    except FileExistsError:
                        pass
                    else:
                        os.close(descriptor)
            connection = sqlite3.connect(resolved, timeout=30, check_same_thread=False)
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        self.init_db()

    def close(self) -> None:
        if self._owns_connection:
            self._connection.close()

    def __enter__(self) -> DeliveryStore:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def init_db(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript("""
                CREATE TABLE IF NOT EXISTS outbound_delivery (
                    provider TEXT NOT NULL, operation_id TEXT NOT NULL, grant_id TEXT NOT NULL,
                    provider_message_id TEXT, rfc_message_id TEXT,
                    status TEXT NOT NULL CHECK(status IN
                        ('awaiting','delivered','bounced','complaint','rejected')),
                    accepted_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_event_at TEXT,
                    PRIMARY KEY(provider, operation_id)
                );
                CREATE INDEX IF NOT EXISTS outbound_delivery_message
                    ON outbound_delivery(provider, grant_id, provider_message_id);
                CREATE INDEX IF NOT EXISTS outbound_delivery_rfc
                    ON outbound_delivery(provider, grant_id, rfc_message_id);
                CREATE TABLE IF NOT EXISTS outbound_delivery_events (
                    provider TEXT NOT NULL, event_id TEXT NOT NULL, event_hash TEXT NOT NULL,
                    grant_id TEXT NOT NULL, status TEXT NOT NULL, occurred_at TEXT NOT NULL,
                    operation_id TEXT, provider_message_id TEXT, rfc_message_id TEXT,
                    matched_operation_id TEXT, disposition TEXT NOT NULL
                        CHECK(disposition IN ('matched','quarantined')),
                    received_at TEXT NOT NULL, PRIMARY KEY(provider, event_id)
                );
                CREATE TABLE IF NOT EXISTS outbound_delivery_worker (
                    id INTEGER PRIMARY KEY CHECK(id=1), last_poll_at TEXT NOT NULL,
                    last_success_at TEXT, last_error_at TEXT, error_code TEXT,
                    last_processed_count INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS outbound_delivery_events_operation
                    ON outbound_delivery_events(provider,grant_id,operation_id)
                    WHERE disposition='quarantined';
                CREATE INDEX IF NOT EXISTS outbound_delivery_events_message
                    ON outbound_delivery_events(provider,grant_id,provider_message_id)
                    WHERE disposition='quarantined';
                CREATE INDEX IF NOT EXISTS outbound_delivery_events_rfc
                    ON outbound_delivery_events(provider,grant_id,rfc_message_id)
                    WHERE disposition='quarantined';
            """)

    @contextmanager
    def _write(self, *, commit: bool = True) -> Iterator[None]:
        with self._lock:
            if not commit and not self._connection.in_transaction:
                raise ValueError("commit=False requires an active caller transaction")
            with self._connection if commit else nullcontext():
                if not self._connection.in_transaction:
                    self._connection.execute("BEGIN IMMEDIATE")
                yield

    def record_acceptance(
        self,
        provider: str,
        operation_id: str,
        *,
        grant_id: str,
        provider_message_id: str | None = None,
        rfc_message_id: str | None = None,
        accepted_at: datetime | None = None,
        commit: bool = True,
    ) -> DeliveryRecord:
        for name, identity in (("provider", provider), ("grant_id", grant_id)):
            _identifier(identity, name)
        if not _OPERATION.fullmatch(operation_id):
            raise ValueError("invalid operation_id")
        for name, value in (
            ("provider_message_id", provider_message_id),
            ("rfc_message_id", rfc_message_id),
        ):
            _identifier(value, name, optional=True)
        now = datetime.now(UTC).isoformat()
        accepted = _utc(accepted_at or datetime.now(UTC)).isoformat()
        with self._write(commit=commit):
            old = self.get(provider, operation_id)
            if old and (
                old.grant_id != grant_id
                or (
                    old.provider_message_id
                    and provider_message_id
                    and old.provider_message_id != provider_message_id
                )
                or (old.rfc_message_id and rfc_message_id and old.rfc_message_id != rfc_message_id)
            ):
                raise ValueError("acceptance identity changed")
            for column, message_identity in (
                ("provider_message_id", provider_message_id),
                ("rfc_message_id", rfc_message_id),
            ):
                if (
                    message_identity
                    and self._connection.execute(
                        f"SELECT 1 FROM outbound_delivery WHERE provider=? AND grant_id=? "
                        f"AND {column}=? AND operation_id!=?",
                        (provider, grant_id, message_identity, operation_id),
                    ).fetchone()
                ):
                    raise ValueError("message identity belongs to another operation")
            self._connection.execute(
                """
                INSERT INTO outbound_delivery VALUES(?,?,?,?,?,'awaiting',?,?,NULL)
                ON CONFLICT(provider,operation_id) DO UPDATE SET
                    provider_message_id=COALESCE(outbound_delivery.provider_message_id,
                                                 excluded.provider_message_id),
                    rfc_message_id=COALESCE(outbound_delivery.rfc_message_id,excluded.rfc_message_id)
            """,
                (
                    provider,
                    operation_id,
                    grant_id,
                    provider_message_id,
                    rfc_message_id,
                    accepted,
                    now,
                ),
            )
            # Events may arrive before the send response is journaled. Reconcile
            # only stored sanitized evidence, including previous unmatched events.
            candidate = self.get(provider, operation_id)
            assert candidate is not None
            rows = self._connection.execute(
                """
                SELECT * FROM outbound_delivery_events
                WHERE provider=? AND grant_id=? AND disposition='quarantined'
                  AND (operation_id=? OR provider_message_id=? OR rfc_message_id=?)
            """,
                (
                    provider,
                    grant_id,
                    operation_id,
                    candidate.provider_message_id,
                    candidate.rfc_message_id,
                ),
            )
            for row in rows:
                self._match_event(self._event(row))
            record = self.get(provider, operation_id)
            assert record is not None
            return record

    def get(self, provider: str, operation_id: str) -> DeliveryRecord | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM outbound_delivery WHERE provider=? AND operation_id=?",
                (provider, operation_id),
            ).fetchone()
            return self._record(row) if row else None

    def list_records(
        self, *, status: DeliveryStatus | None = None, limit: int = 100
    ) -> tuple[DeliveryRecord, ...]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM outbound_delivery WHERE (? IS NULL OR status=?)
                ORDER BY accepted_at DESC LIMIT ?
            """,
                (status, status, limit),
            ).fetchall()
            return tuple(self._record(row) for row in rows)

    def apply_event(self, event: DeliveryEvent) -> EventResult:
        digest = sha256(
            json.dumps(event.as_dict(), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        with self._write():
            previous = self._connection.execute(
                "SELECT * FROM outbound_delivery_events WHERE provider=? AND event_id=?",
                (event.provider, event.event_id),
            ).fetchone()
            if previous:
                if previous["event_hash"] != digest:
                    raise ValueError("delivery event identity conflict")
                return EventResult(
                    str(previous["disposition"]), True, previous["matched_operation_id"]
                )
            self._connection.execute(
                """
                INSERT INTO outbound_delivery_events VALUES
                    (?,?,?,?,?,?,?,?,?,NULL,'quarantined',?)
            """,
                (
                    event.provider,
                    event.event_id,
                    digest,
                    event.grant_id,
                    event.status,
                    _utc(event.occurred_at).isoformat(),
                    event.operation_id,
                    event.provider_message_id,
                    event.rfc_message_id,
                    datetime.now(UTC).isoformat(),
                ),
            )
            return self._match_event(event)

    def _match_event(self, event: DeliveryEvent) -> EventResult:
        candidates: set[str] = set()
        for column, value in (
            ("operation_id", event.operation_id),
            ("provider_message_id", event.provider_message_id),
            ("rfc_message_id", event.rfc_message_id),
        ):
            if value:
                rows = self._connection.execute(
                    f"SELECT operation_id FROM outbound_delivery WHERE provider=? "
                    f"AND grant_id=? AND {column}=?",
                    (event.provider, event.grant_id, value),
                ).fetchall()
                candidates.update(str(row[0]) for row in rows)
        if len(candidates) != 1:
            return EventResult("quarantined", False, None)
        operation_id = next(iter(candidates))
        record = self.get(event.provider, operation_id)
        assert record is not None
        if (
            (event.operation_id and event.operation_id != operation_id)
            or (
                event.provider_message_id
                and record.provider_message_id
                and event.provider_message_id != record.provider_message_id
            )
            or (
                event.rfc_message_id
                and record.rfc_message_id
                and event.rfc_message_id != record.rfc_message_id
            )
        ):
            return EventResult("quarantined", False, None)
        status = max((record.status, event.status), key=_PRIORITY.__getitem__)
        last = max(filter(None, (record.last_event_at, _utc(event.occurred_at))))
        self._connection.execute(
            """
            UPDATE outbound_delivery SET status=?,updated_at=?,last_event_at=?,
                provider_message_id=COALESCE(provider_message_id,?),
                rfc_message_id=COALESCE(rfc_message_id,?)
            WHERE provider=? AND operation_id=?
        """,
            (
                status,
                datetime.now(UTC).isoformat(),
                last.isoformat(),
                event.provider_message_id,
                event.rfc_message_id,
                event.provider,
                operation_id,
            ),
        )
        self._connection.execute(
            """
            UPDATE outbound_delivery_events SET disposition='matched',matched_operation_id=?
            WHERE provider=? AND event_id=?
        """,
            (operation_id, event.provider, event.event_id),
        )
        return EventResult("matched", False, operation_id)

    def worker_poll(self, *, processed: int = 0, error_code: str | None = None) -> None:
        if error_code not in {None, "queue_error", "event_error"}:
            raise ValueError("unsupported safe error code")
        now = datetime.now(UTC).isoformat()
        with self._write():
            self._connection.execute(
                """
                INSERT INTO outbound_delivery_worker VALUES(1,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET last_poll_at=excluded.last_poll_at,
                    last_success_at=COALESCE(excluded.last_success_at,last_success_at),
                    last_error_at=COALESCE(excluded.last_error_at,last_error_at),
                    error_code=excluded.error_code,last_processed_count=excluded.last_processed_count
            """,
                (
                    now,
                    now if error_code is None else None,
                    now if error_code else None,
                    error_code,
                    processed,
                ),
            )

    def health(self, *, overdue_seconds: int = 600, now: datetime | None = None) -> dict[str, Any]:
        if overdue_seconds <= 0:
            raise ValueError("overdue_seconds must be positive")
        current = _utc(now or datetime.now(UTC))
        with self._lock:
            counts = {
                str(row[0]): int(row[1])
                for row in self._connection.execute(
                    "SELECT status,COUNT(*) FROM outbound_delivery GROUP BY status"
                ).fetchall()
            }
            overdue = self._connection.execute(
                """
                SELECT COUNT(*) FROM outbound_delivery WHERE status='awaiting' AND accepted_at<=?
            """,
                ((current - timedelta(seconds=overdue_seconds)).isoformat(),),
            ).fetchone()[0]
            quarantined = self._connection.execute("""
                SELECT COUNT(*) FROM outbound_delivery_events WHERE disposition='quarantined'
            """).fetchone()[0]
            worker = self._connection.execute(
                "SELECT * FROM outbound_delivery_worker WHERE id=1"
            ).fetchone()
            return {
                "counts": counts,
                "awaiting_overdue": int(overdue),
                "quarantined_events": int(quarantined),
                "worker": dict(worker) if worker else None,
                "checked_at": current.isoformat(),
            }

    @staticmethod
    def _event(row: sqlite3.Row) -> DeliveryEvent:
        return DeliveryEvent(
            event_id=row["event_id"],
            provider=row["provider"],
            grant_id=row["grant_id"],
            status=DeliveryStatus(row["status"]),
            occurred_at=datetime.fromisoformat(row["occurred_at"]),
            operation_id=row["operation_id"],
            provider_message_id=row["provider_message_id"],
            rfc_message_id=row["rfc_message_id"],
        )

    @staticmethod
    def _record(row: sqlite3.Row) -> DeliveryRecord:
        return DeliveryRecord(
            provider=row["provider"],
            operation_id=row["operation_id"],
            grant_id=row["grant_id"],
            provider_message_id=row["provider_message_id"],
            rfc_message_id=row["rfc_message_id"],
            status=DeliveryStatus(row["status"]),
            accepted_at=datetime.fromisoformat(row["accepted_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            last_event_at=datetime.fromisoformat(row["last_event_at"])
            if row["last_event_at"]
            else None,
        )
