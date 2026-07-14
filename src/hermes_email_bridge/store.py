"""SQLite-backed conversation mappings, provider cursors, and idempotency."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .mapping import extract_bridge_marker, normalize_email_address, normalize_subject
from .models import (
    AllowlistEntry,
    ConversationMapping,
    MappingResolution,
    NormalizedEmail,
    ResolutionStatus,
    SenderAuthentication,
    SentEmail,
    utc_now,
)

_SCHEMA_VERSION = 2
_LEGACY_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS mappings (
        id INTEGER PRIMARY KEY,
        provider TEXT NOT NULL,
        hermes_session TEXT NOT NULL,
        hermes_topic TEXT,
        provider_thread_id TEXT,
        subject_key TEXT,
        participant_email TEXT,
        bridge_marker TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS mappings_subject
        ON mappings(provider, subject_key, participant_email)
    """,
    """
    CREATE TABLE IF NOT EXISTS message_links (
        provider TEXT NOT NULL,
        message_id TEXT NOT NULL,
        mapping_id INTEGER NOT NULL REFERENCES mappings(id) ON DELETE CASCADE,
        PRIMARY KEY (provider, message_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS cursors (
        provider TEXT PRIMARY KEY,
        cursor TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS processed_messages (
        provider TEXT NOT NULL,
        message_id TEXT NOT NULL,
        processed_at TEXT NOT NULL,
        outcome TEXT NOT NULL,
        raw_payload TEXT,
        PRIMARY KEY (provider, message_id)
    )
    """,
)


class MappingStore:
    def __init__(self, path: str | Path) -> None:
        self.path = str(Path(path).expanduser()) if str(path) != ":memory:" else ":memory:"
        if self.path != ":memory:":
            self._prepare_database_path(Path(self.path))
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        try:
            self.init_db()
        except Exception:
            self._connection.close()
            raise

    @staticmethod
    def _prepare_database_path(path: Path) -> None:
        parent_was_missing = not path.parent.exists()
        path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "posix" and parent_was_missing:
            path.parent.chmod(0o700)
        if path.exists():
            return
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return
        os.close(descriptor)
        if os.name == "posix":
            path.chmod(0o600)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> MappingStore:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def init_db(self) -> None:
        with self._lock:
            self._connection.execute("PRAGMA foreign_keys = ON")
            version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
            if version > _SCHEMA_VERSION:
                raise RuntimeError(
                    f"database schema version {version} is newer than supported "
                    f"version {_SCHEMA_VERSION}"
                )
            if version == _SCHEMA_VERSION:
                return
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                for statement in _LEGACY_SCHEMA:
                    self._connection.execute(statement)
                columns = {
                    str(row[1])
                    for row in self._connection.execute("PRAGMA table_info(mappings)").fetchall()
                }
                if "bridge_marker_expires_at" not in columns:
                    self._connection.execute(
                        "ALTER TABLE mappings ADD COLUMN bridge_marker_expires_at TEXT"
                    )
                self._connection.execute("DROP INDEX IF EXISTS mappings_provider_thread")
                self._connection.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS mappings_provider_thread_participant
                    ON mappings(provider, provider_thread_id, participant_email)
                    WHERE provider_thread_id IS NOT NULL AND participant_email IS NOT NULL
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS email_allowlist (
                        provider TEXT NOT NULL,
                        address TEXT NOT NULL,
                        source TEXT NOT NULL,
                        source_message_id TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        revoked_at TEXT,
                        PRIMARY KEY (provider, address)
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS observed_sent_messages (
                        provider TEXT NOT NULL,
                        message_id TEXT NOT NULL,
                        observed_at TEXT NOT NULL,
                        PRIMARY KEY (provider, message_id)
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS poll_starts (
                        cursor_key TEXT PRIMARY KEY,
                        started_at TEXT NOT NULL
                    )
                    """
                )
                self._connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    def add_mapping(
        self,
        *,
        provider: str,
        hermes_session: str,
        hermes_topic: str | None = None,
        provider_thread_id: str | None = None,
        subject: str | None = None,
        participant_email: str | None = None,
        bridge_marker: str | None = None,
        marker_ttl_days: int = 90,
        message_ids: tuple[str, ...] = (),
    ) -> ConversationMapping:
        if not hermes_session.strip():
            raise ValueError("hermes_session cannot be empty")
        if marker_ttl_days <= 0:
            raise ValueError("marker_ttl_days must be positive")
        now = utc_now()
        marker = bridge_marker or secrets.token_urlsafe(24)
        marker_expires_at = now + timedelta(days=marker_ttl_days)
        subject_key = normalize_subject(subject) if subject else None
        participant = participant_email.strip().lower() if participant_email else None
        with self._lock, self._connection:
            row = None
            if provider_thread_id:
                row = self._connection.execute(
                    """
                    SELECT * FROM mappings
                    WHERE provider = ? AND provider_thread_id = ?
                      AND (participant_email = ? OR (participant_email IS NULL AND ? IS NULL))
                    """,
                    (provider, provider_thread_id, participant, participant),
                ).fetchone()
            if row:
                mapping_id = int(row["id"])
                if str(row["hermes_session"]) != hermes_session:
                    raise ValueError(
                        "provider thread and participant are already mapped to a different "
                        "Hermes session"
                    )
                if bridge_marker is not None and str(row["bridge_marker"]) != bridge_marker:
                    raise ValueError("existing mapping has a different bridge marker")
                self._connection.execute(
                    """
                    UPDATE mappings
                    SET hermes_topic = COALESCE(?, hermes_topic),
                        subject_key = COALESCE(?, subject_key), updated_at = ?
                    WHERE id = ?
                    """,
                    (hermes_topic, subject_key, now.isoformat(), mapping_id),
                )
            else:
                cursor = self._connection.execute(
                    """
                    INSERT INTO mappings (
                        provider, hermes_session, hermes_topic, provider_thread_id,
                        subject_key, participant_email, bridge_marker,
                        bridge_marker_expires_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        provider,
                        hermes_session,
                        hermes_topic,
                        provider_thread_id,
                        subject_key,
                        participant,
                        marker,
                        marker_expires_at.isoformat(),
                        now.isoformat(),
                        now.isoformat(),
                    ),
                )
                if cursor.lastrowid is None:
                    raise RuntimeError("SQLite did not return a mapping ID")
                mapping_id = cursor.lastrowid
            for message_id in message_ids:
                self._link_message(provider, message_id, mapping_id)
            return self._get_mapping(mapping_id)

    def rotate_mapping_marker(self, mapping_id: int, *, ttl_days: int = 90) -> ConversationMapping:
        if ttl_days <= 0:
            raise ValueError("ttl_days must be positive")
        marker = secrets.token_urlsafe(24)
        now = utc_now()
        expires_at = now + timedelta(days=ttl_days)
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE mappings
                SET bridge_marker = ?, bridge_marker_expires_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (marker, expires_at.isoformat(), now.isoformat(), mapping_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(mapping_id)
            return self._get_mapping(mapping_id)

    def update_mapping_session(
        self,
        mapping_id: int,
        *,
        expected_session: str,
        new_session: str,
    ) -> ConversationMapping:
        """Atomically accept a valid session rotation returned by Hermes."""

        if not new_session.strip():
            raise ValueError("new_session cannot be empty")
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE mappings SET hermes_session = ?, updated_at = ?
                WHERE id = ? AND hermes_session = ?
                """,
                (new_session, utc_now().isoformat(), mapping_id, expected_session),
            )
            if cursor.rowcount != 1:
                raise ValueError("mapping session changed concurrently")
            return self._get_mapping(mapping_id)

    def add_message_link(self, provider: str, message_id: str, mapping_id: int) -> None:
        with self._lock, self._connection:
            self._link_message(provider, message_id, mapping_id)

    def _link_message(self, provider: str, message_id: str, mapping_id: int) -> None:
        self._connection.execute(
            """
            INSERT INTO message_links(provider, message_id, mapping_id)
            VALUES (?, ?, ?)
            ON CONFLICT(provider, message_id) DO NOTHING
            """,
            (provider, message_id, mapping_id),
        )
        linked = self._connection.execute(
            """
            SELECT mapping_id FROM message_links
            WHERE provider = ? AND message_id = ?
            """,
            (provider, message_id),
        ).fetchone()
        if linked is None or int(linked["mapping_id"]) != mapping_id:
            raise ValueError("provider message is already linked to a different mapping")

    def resolve(
        self, message: NormalizedEmail, *, allow_subject_resume: bool = False
    ) -> MappingResolution:
        if (
            message.sender_authentication is not SenderAuthentication.AUTHENTICATED
            or not self._participant(message)
        ):
            return MappingResolution(ResolutionStatus.DENIED, matched_by="sender_authentication")

        with self._lock:
            marker = extract_bridge_marker(message.raw_payload)
            if marker:
                row = self._connection.execute(
                    "SELECT * FROM mappings WHERE provider = ? AND bridge_marker = ?",
                    (message.provider, marker),
                ).fetchone()
                if row:
                    mapping = self._row_to_mapping(row)
                    if (
                        mapping.bridge_marker_expires_at is not None
                        and mapping.bridge_marker_expires_at <= utc_now()
                    ):
                        return MappingResolution(
                            ResolutionStatus.DENIED, matched_by="expired_bridge_marker"
                        )
                    return self._authorize_candidate(mapping, message, "bridge_marker")

            reply_ids = [message.in_reply_to, *reversed(message.references)]
            for message_id in reply_ids:
                if not message_id:
                    continue
                row = self._connection.execute(
                    """
                    SELECT mappings.* FROM mappings
                    JOIN message_links ON message_links.mapping_id = mappings.id
                    WHERE message_links.provider = ? AND message_links.message_id = ?
                    """,
                    (message.provider, message_id),
                ).fetchone()
                if row:
                    method = "in_reply_to" if message_id == message.in_reply_to else "references"
                    return self._authorize_candidate(self._row_to_mapping(row), message, method)

            if message.thread_id:
                rows = self._connection.execute(
                    """
                    SELECT * FROM mappings
                    WHERE provider = ? AND provider_thread_id = ?
                    ORDER BY updated_at DESC
                    """,
                    (message.provider, message.thread_id),
                ).fetchall()
                for row in rows:
                    mapping = self._row_to_mapping(row)
                    if mapping.participant_email == self._participant(message):
                        return MappingResolution(ResolutionStatus.AUTHORIZED, mapping, "thread_id")
                if rows:
                    return MappingResolution(ResolutionStatus.DENIED, matched_by="thread_id")

            if allow_subject_resume:
                subject_key = normalize_subject(message.subject)
                if subject_key:
                    row = self._connection.execute(
                        """
                        SELECT * FROM mappings
                        WHERE provider = ? AND subject_key = ? AND participant_email = ?
                        ORDER BY updated_at DESC
                        LIMIT 1
                        """,
                        (message.provider, subject_key, self._participant(message)),
                    ).fetchone()
                    if row:
                        return MappingResolution(
                            ResolutionStatus.AUTHORIZED,
                            self._row_to_mapping(row),
                            "subject",
                        )
        return MappingResolution(ResolutionStatus.NO_MATCH)

    @classmethod
    def _authorize_candidate(
        cls,
        mapping: ConversationMapping,
        message: NormalizedEmail,
        matched_by: str,
    ) -> MappingResolution:
        if mapping.participant_email and mapping.participant_email == cls._participant(message):
            return MappingResolution(ResolutionStatus.AUTHORIZED, mapping, matched_by)
        return MappingResolution(ResolutionStatus.DENIED, matched_by=matched_by)

    @staticmethod
    def _participant(message: NormalizedEmail) -> str:
        return message.from_email.strip().lower()

    def list_mappings(self) -> list[ConversationMapping]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM mappings ORDER BY updated_at DESC"
            ).fetchall()
            return [self._row_to_mapping(row) for row in rows]

    def add_allowed_address(
        self,
        provider: str,
        address: str,
        *,
        source: str = "manual",
        source_message_id: str | None = None,
    ) -> AllowlistEntry:
        normalized = normalize_email_address(address)
        now = utc_now().isoformat()
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO email_allowlist(
                    provider, address, source, source_message_id, created_at, updated_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(provider, address) DO UPDATE SET
                    source = excluded.source,
                    source_message_id = excluded.source_message_id,
                    updated_at = excluded.updated_at,
                    revoked_at = NULL
                """,
                (provider, normalized, source, source_message_id, now, now),
            )
            row = self._connection.execute(
                "SELECT * FROM email_allowlist WHERE provider = ? AND address = ?",
                (provider, normalized),
            ).fetchone()
            if row is None:
                raise RuntimeError("allowlist insert failed")
            return self._row_to_allowlist(row)

    def remove_allowed_address(
        self, provider: str, address: str, *, now: datetime | None = None
    ) -> bool:
        normalized = normalize_email_address(address)
        removed_at = (now or utc_now()).isoformat()
        with self._lock, self._connection:
            row = self._connection.execute(
                """
                SELECT revoked_at FROM email_allowlist
                WHERE provider = ? AND address = ?
                """,
                (provider, normalized),
            ).fetchone()
            was_active = row is not None and row["revoked_at"] is None
            self._connection.execute(
                """
                INSERT INTO email_allowlist(
                    provider, address, source, source_message_id,
                    created_at, updated_at, revoked_at
                ) VALUES (?, ?, 'revoked', NULL, ?, ?, ?)
                ON CONFLICT(provider, address) DO UPDATE SET
                    source = 'revoked',
                    source_message_id = NULL,
                    updated_at = excluded.updated_at,
                    revoked_at = excluded.revoked_at
                """,
                (provider, normalized, removed_at, removed_at, removed_at),
            )
            return was_active

    def is_allowed(self, provider: str, address: str) -> bool:
        try:
            normalized = normalize_email_address(address)
        except ValueError:
            return False
        with self._lock:
            row = self._connection.execute(
                """
                SELECT 1 FROM email_allowlist
                WHERE provider = ? AND address = ? AND revoked_at IS NULL
                """,
                (provider, normalized),
            ).fetchone()
            return row is not None

    def list_allowed_addresses(self, provider: str) -> list[AllowlistEntry]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM email_allowlist
                WHERE provider = ? AND revoked_at IS NULL
                ORDER BY address
                """,
                (provider,),
            ).fetchall()
            return [self._row_to_allowlist(row) for row in rows]

    def enroll_sent_message(self, message: SentEmail) -> int:
        """Authorize recipients once per trusted outbound message."""

        now = utc_now().isoformat()
        with self._lock, self._connection:
            inserted = self._connection.execute(
                """
                INSERT INTO observed_sent_messages(provider, message_id, observed_at)
                VALUES (?, ?, ?)
                ON CONFLICT(provider, message_id) DO NOTHING
                """,
                (message.provider, message.provider_message_id, now),
            )
            if inserted.rowcount != 1:
                return 0
            count = 0
            for address in message.recipients:
                try:
                    normalized = normalize_email_address(address)
                except ValueError:
                    continue
                existing = self._connection.execute(
                    """
                    SELECT revoked_at FROM email_allowlist
                    WHERE provider = ? AND address = ?
                    """,
                    (message.provider, normalized),
                ).fetchone()
                if existing is not None and existing["revoked_at"] is not None:
                    revoked_at = datetime.fromisoformat(str(existing["revoked_at"]))
                    if message.sent_at <= revoked_at:
                        continue
                self._connection.execute(
                    """
                    INSERT INTO email_allowlist(
                        provider, address, source, source_message_id,
                        created_at, updated_at, revoked_at
                    ) VALUES (?, ?, 'sent', ?, ?, ?, NULL)
                    ON CONFLICT(provider, address) DO UPDATE SET
                        source = 'sent',
                        source_message_id = excluded.source_message_id,
                        updated_at = excluded.updated_at,
                        revoked_at = NULL
                    """,
                    (
                        message.provider,
                        normalized,
                        message.provider_message_id,
                        now,
                        now,
                    ),
                )
                count += 1
            return count

    def seed_poll_cursors(self, provider: str, *, now: datetime | None = None) -> tuple[str, ...]:
        """Atomically seed missing inbound/sent cursors and their no-history floors."""

        timestamp = (now or utc_now()).astimezone(UTC).isoformat().replace("+00:00", "Z")
        seeded: list[str] = []
        with self._lock, self._connection:
            for cursor_key in (provider, f"{provider}:sent"):
                cursor = self._connection.execute(
                    """
                    INSERT INTO cursors(provider, cursor, updated_at) VALUES (?, ?, ?)
                    ON CONFLICT(provider) DO NOTHING
                    """,
                    (cursor_key, timestamp, timestamp),
                )
                if cursor.rowcount == 1:
                    self._connection.execute(
                        "INSERT INTO poll_starts(cursor_key, started_at) VALUES (?, ?)",
                        (cursor_key, timestamp),
                    )
                    seeded.append(cursor_key)
        return tuple(seeded)

    def get_poll_start(self, cursor_key: str) -> datetime | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT started_at FROM poll_starts WHERE cursor_key = ?", (cursor_key,)
            ).fetchone()
            return (
                datetime.fromisoformat(str(row["started_at"]).replace("Z", "+00:00"))
                if row
                else None
            )

    def get_cursor(self, provider: str) -> str | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT cursor FROM cursors WHERE provider = ?", (provider,)
            ).fetchone()
            return str(row["cursor"]) if row else None

    def set_cursor(self, provider: str, cursor: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO cursors(provider, cursor, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(provider) DO UPDATE
                SET cursor = excluded.cursor, updated_at = excluded.updated_at
                """,
                (provider, cursor, utc_now().isoformat()),
            )

    def is_processed(self, provider: str, message_id: str) -> bool:
        with self._lock:
            row = self._connection.execute(
                "SELECT 1 FROM processed_messages WHERE provider = ? AND message_id = ?",
                (provider, message_id),
            ).fetchone()
            return row is not None

    def mark_processed(
        self,
        message: NormalizedEmail,
        outcome: str,
        *,
        store_raw: bool,
        raw_retention_days: int = 30,
    ) -> None:
        if raw_retention_days <= 0:
            raise ValueError("raw_retention_days must be positive")
        raw = json.dumps(message.raw_payload, default=str, sort_keys=True) if store_raw else None
        now = utc_now()
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO processed_messages(
                    provider, message_id, processed_at, outcome, raw_payload
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(provider, message_id) DO UPDATE
                SET processed_at = excluded.processed_at,
                    outcome = excluded.outcome,
                    raw_payload = excluded.raw_payload
                """,
                (
                    message.provider,
                    message.provider_message_id,
                    now.isoformat(),
                    outcome,
                    raw,
                ),
            )
            self._purge_raw_before(now - timedelta(days=raw_retention_days))

    def purge_raw(self, older_than_days: int, *, now: datetime | None = None) -> int:
        if older_than_days <= 0:
            raise ValueError("older_than_days must be positive")
        cutoff = (now or utc_now()) - timedelta(days=older_than_days)
        with self._lock, self._connection:
            return self._purge_raw_before(cutoff)

    def _purge_raw_before(self, cutoff: datetime) -> int:
        cursor = self._connection.execute(
            """
            UPDATE processed_messages SET raw_payload = NULL
            WHERE raw_payload IS NOT NULL AND processed_at < ?
            """,
            (cutoff.isoformat(),),
        )
        return cursor.rowcount

    def _get_mapping(self, mapping_id: int) -> ConversationMapping:
        row = self._connection.execute(
            "SELECT * FROM mappings WHERE id = ?", (mapping_id,)
        ).fetchone()
        if row is None:
            raise KeyError(mapping_id)
        return self._row_to_mapping(row)

    @staticmethod
    def _row_to_mapping(row: sqlite3.Row) -> ConversationMapping:
        values: dict[str, Any] = dict(row)
        return ConversationMapping(
            id=int(values["id"]),
            provider=str(values["provider"]),
            hermes_session=str(values["hermes_session"]),
            hermes_topic=_optional_string(values["hermes_topic"]),
            provider_thread_id=_optional_string(values["provider_thread_id"]),
            subject_key=_optional_string(values["subject_key"]),
            participant_email=_optional_string(values["participant_email"]),
            bridge_marker=str(values["bridge_marker"]),
            bridge_marker_expires_at=_optional_datetime(values.get("bridge_marker_expires_at")),
            created_at=datetime.fromisoformat(str(values["created_at"])),
            updated_at=datetime.fromisoformat(str(values["updated_at"])),
        )

    @staticmethod
    def _row_to_allowlist(row: sqlite3.Row) -> AllowlistEntry:
        return AllowlistEntry(
            provider=str(row["provider"]),
            address=str(row["address"]),
            source=str(row["source"]),
            source_message_id=_optional_string(row["source_message_id"]),
            created_at=datetime.fromisoformat(str(row["created_at"])),
            updated_at=datetime.fromisoformat(str(row["updated_at"])),
            revoked_at=_optional_datetime(row["revoked_at"]),
        )


def _optional_string(value: Any) -> str | None:
    return str(value) if value is not None else None


def _optional_datetime(value: Any) -> datetime | None:
    return datetime.fromisoformat(str(value)) if value is not None else None
