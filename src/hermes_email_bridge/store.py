"""SQLite-backed conversation mappings, provider cursors, and idempotency."""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from .mapping import extract_bridge_marker, normalize_subject
from .models import ConversationMapping, NormalizedEmail, ResolvedMapping, utc_now

_SCHEMA = """
PRAGMA foreign_keys = ON;
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
);
CREATE UNIQUE INDEX IF NOT EXISTS mappings_provider_thread
    ON mappings(provider, provider_thread_id)
    WHERE provider_thread_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS mappings_subject
    ON mappings(provider, subject_key, participant_email);
CREATE TABLE IF NOT EXISTS message_links (
    provider TEXT NOT NULL,
    message_id TEXT NOT NULL,
    mapping_id INTEGER NOT NULL REFERENCES mappings(id) ON DELETE CASCADE,
    PRIMARY KEY (provider, message_id)
);
CREATE TABLE IF NOT EXISTS cursors (
    provider TEXT PRIMARY KEY,
    cursor TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS processed_messages (
    provider TEXT NOT NULL,
    message_id TEXT NOT NULL,
    processed_at TEXT NOT NULL,
    outcome TEXT NOT NULL,
    raw_payload TEXT,
    PRIMARY KEY (provider, message_id)
);
"""


class MappingStore:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self.init_db()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> MappingStore:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def init_db(self) -> None:
        with self._lock:
            self._connection.executescript(_SCHEMA)
            self._connection.commit()

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
        message_ids: tuple[str, ...] = (),
    ) -> ConversationMapping:
        if not hermes_session.strip():
            raise ValueError("hermes_session cannot be empty")
        now = utc_now().isoformat()
        marker = bridge_marker or secrets.token_urlsafe(24)
        subject_key = normalize_subject(subject) if subject else None
        participant = participant_email.strip().lower() if participant_email else None
        with self._lock:
            row = None
            if provider_thread_id:
                row = self._connection.execute(
                    "SELECT id FROM mappings WHERE provider = ? AND provider_thread_id = ?",
                    (provider, provider_thread_id),
                ).fetchone()
            if row:
                mapping_id = int(row["id"])
                self._connection.execute(
                    """
                    UPDATE mappings
                    SET hermes_session = ?, hermes_topic = ?,
                        subject_key = COALESCE(?, subject_key),
                        participant_email = COALESCE(?, participant_email), updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        hermes_session,
                        hermes_topic,
                        subject_key,
                        participant,
                        now,
                        mapping_id,
                    ),
                )
            else:
                cursor = self._connection.execute(
                    """
                    INSERT INTO mappings (
                        provider, hermes_session, hermes_topic, provider_thread_id,
                        subject_key, participant_email, bridge_marker, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        provider,
                        hermes_session,
                        hermes_topic,
                        provider_thread_id,
                        subject_key,
                        participant,
                        marker,
                        now,
                        now,
                    ),
                )
                if cursor.lastrowid is None:
                    raise RuntimeError("SQLite did not return a mapping ID")
                mapping_id = cursor.lastrowid
            for message_id in message_ids:
                self._link_message(provider, message_id, mapping_id)
            self._connection.commit()
            return self._get_mapping(mapping_id)

    def add_message_link(self, provider: str, message_id: str, mapping_id: int) -> None:
        with self._lock:
            self._link_message(provider, message_id, mapping_id)
            self._connection.commit()

    def _link_message(self, provider: str, message_id: str, mapping_id: int) -> None:
        self._connection.execute(
            """
            INSERT INTO message_links(provider, message_id, mapping_id)
            VALUES (?, ?, ?)
            ON CONFLICT(provider, message_id) DO UPDATE SET mapping_id = excluded.mapping_id
            """,
            (provider, message_id, mapping_id),
        )

    def resolve(self, message: NormalizedEmail) -> ResolvedMapping | None:
        with self._lock:
            marker = extract_bridge_marker(message.raw_payload)
            if marker:
                row = self._connection.execute(
                    "SELECT * FROM mappings WHERE provider = ? AND bridge_marker = ?",
                    (message.provider, marker),
                ).fetchone()
                if row:
                    return ResolvedMapping(self._row_to_mapping(row), "bridge_marker")

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
                    return ResolvedMapping(self._row_to_mapping(row), method)

            if message.thread_id:
                row = self._connection.execute(
                    "SELECT * FROM mappings WHERE provider = ? AND provider_thread_id = ?",
                    (message.provider, message.thread_id),
                ).fetchone()
                if row:
                    return ResolvedMapping(self._row_to_mapping(row), "thread_id")

            subject_key = normalize_subject(message.subject)
            if subject_key:
                row = self._connection.execute(
                    """
                    SELECT * FROM mappings
                    WHERE provider = ? AND subject_key = ?
                      AND (participant_email = ? OR participant_email IS NULL)
                    ORDER BY participant_email IS NULL, updated_at DESC
                    LIMIT 1
                    """,
                    (message.provider, subject_key, message.from_email.lower()),
                ).fetchone()
                if row:
                    return ResolvedMapping(self._row_to_mapping(row), "subject")
        return None

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
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO cursors(provider, cursor, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(provider) DO UPDATE
                SET cursor = excluded.cursor, updated_at = excluded.updated_at
                """,
                (provider, cursor, utc_now().isoformat()),
            )
            self._connection.commit()

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
    ) -> None:
        raw = json.dumps(message.raw_payload, default=str, sort_keys=True) if store_raw else None
        with self._lock:
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
                    utc_now().isoformat(),
                    outcome,
                    raw,
                ),
            )
            self._connection.commit()

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
            created_at=datetime.fromisoformat(str(values["created_at"])),
            updated_at=datetime.fromisoformat(str(values["updated_at"])),
        )


def _optional_string(value: Any) -> str | None:
    return str(value) if value is not None else None
