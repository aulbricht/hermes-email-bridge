"""SQLite-backed conversation mappings, provider cursors, and idempotency."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .mapping import extract_bridge_marker, normalize_subject
from .models import (
    ConversationMapping,
    MappingResolution,
    NormalizedEmail,
    ResolutionStatus,
    SenderAuthentication,
    utc_now,
)

_SCHEMA_VERSION = 1
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
    CREATE UNIQUE INDEX IF NOT EXISTS mappings_provider_thread
        ON mappings(provider, provider_thread_id)
        WHERE provider_thread_id IS NOT NULL
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


def _optional_string(value: Any) -> str | None:
    return str(value) if value is not None else None


def _optional_datetime(value: Any) -> datetime | None:
    return datetime.fromisoformat(str(value)) if value is not None else None
