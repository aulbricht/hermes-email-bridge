import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from hermes_email_bridge.models import (
    NormalizedEmail,
    ResolutionStatus,
    SenderAuthentication,
    SentEmail,
)
from hermes_email_bridge.store import MappingStore


def _message(
    *,
    message_id: str = "<inbound@example.com>",
    from_email: str = "person@example.com",
    subject: str = "Re: Project Atlas",
    in_reply_to: str | None = None,
    references: tuple[str, ...] = (),
    headers: dict[str, str] | None = None,
    thread_id: str | None = "thread-1",
    authentication: SenderAuthentication = SenderAuthentication.AUTHENTICATED,
) -> NormalizedEmail:
    return NormalizedEmail(
        provider="agentmail",
        provider_message_id=message_id,
        from_email=from_email,
        to_email="bridge@agentmail.to",
        subject=subject,
        text_body="reply",
        received_at=datetime(2026, 7, 9, tzinfo=UTC),
        in_reply_to=in_reply_to,
        references=references,
        thread_id=thread_id,
        raw_payload={"headers": headers or {}},
        sender_authentication=authentication,
    )


def test_authenticated_participant_resolves_all_supported_paths(tmp_path: Path) -> None:
    marker = "abcdefghijklmnopqrstuvwxyz_123456"
    with MappingStore(tmp_path / "bridge.db") as store:
        mapping = store.add_mapping(
            provider="agentmail",
            hermes_session="session-1",
            provider_thread_id="original-thread",
            subject="Project Atlas",
            participant_email="person@example.com",
            bridge_marker=marker,
            message_ids=("<outbound@example.com>",),
        )
        messages = (
            (_message(in_reply_to="<outbound@example.com>", thread_id=None), "in_reply_to"),
            (
                _message(
                    message_id="<reference@example.com>",
                    references=("<outbound@example.com>",),
                    thread_id=None,
                ),
                "references",
            ),
            (_message(thread_id="original-thread"), "thread_id"),
            (
                _message(
                    thread_id=None,
                    headers={"X-Hermes-Bridge": f"v1:{marker}"},
                ),
                "bridge_marker",
            ),
        )
        for message, method in messages:
            resolution = store.resolve(message)
            assert resolution.status is ResolutionStatus.AUTHORIZED
            assert resolution.mapping and resolution.mapping.id == mapping.id
            assert resolution.matched_by == method

        subject = store.resolve(_message(thread_id=None))
        assert subject.status is ResolutionStatus.NO_MATCH
        enabled_subject = store.resolve(_message(thread_id=None), allow_subject_resume=True)
        assert enabled_subject.status is ResolutionStatus.AUTHORIZED
        assert enabled_subject.matched_by == "subject"


@pytest.mark.parametrize(
    ("authentication", "from_email"),
    [
        (SenderAuthentication.UNAUTHENTICATED, "person@example.com"),
        (SenderAuthentication.UNKNOWN, "person@example.com"),
        (SenderAuthentication.AUTHENTICATED, "attacker@example.com"),
    ],
)
def test_spoofed_resume_attributes_are_denied(
    tmp_path: Path,
    authentication: SenderAuthentication,
    from_email: str,
) -> None:
    marker = "abcdefghijklmnopqrstuvwxyz_123456"
    with MappingStore(tmp_path / "bridge.db") as store:
        store.add_mapping(
            provider="agentmail",
            hermes_session="session-1",
            provider_thread_id="thread-1",
            subject="Project Atlas",
            participant_email="person@example.com",
            bridge_marker=marker,
            message_ids=("<outbound@example.com>",),
        )
        forged = _message(
            from_email=from_email,
            authentication=authentication,
            in_reply_to="<outbound@example.com>",
            headers={
                "Authentication-Results": "mx.example; dkim=fail; dmarc=fail",
                "X-Hermes-Bridge": f"v1:{marker}",
            },
        )
        resolution = store.resolve(forged, allow_subject_resume=True)

        assert resolution.status is ResolutionStatus.DENIED
        assert resolution.mapping is None


def test_null_participant_mapping_is_retained_but_not_resumable(tmp_path: Path) -> None:
    with MappingStore(tmp_path / "bridge.db") as store:
        mapping = store.add_mapping(
            provider="agentmail",
            hermes_session="legacy-session",
            provider_thread_id="legacy-thread",
        )
        assert mapping.participant_email is None
        resolution = store.resolve(_message(thread_id="legacy-thread"))
        assert resolution.status is ResolutionStatus.DENIED


def test_thread_conflict_never_overwrites_session(tmp_path: Path) -> None:
    with MappingStore(tmp_path / "bridge.db") as store:
        original = store.add_mapping(
            provider="agentmail",
            hermes_session="session-1",
            provider_thread_id="thread-1",
            participant_email="person@example.com",
        )
        with pytest.raises(ValueError, match="different Hermes session"):
            store.add_mapping(
                provider="agentmail",
                hermes_session="session-2",
                provider_thread_id="thread-1",
                participant_email="person@example.com",
            )
        assert store.list_mappings()[0].hermes_session == original.hermes_session

        other = store.add_mapping(
            provider="agentmail",
            hermes_session="session-2",
            provider_thread_id="thread-1",
            participant_email="other@example.com",
        )
        assert other.id != original.id


def test_marker_rotation_and_expiry(tmp_path: Path) -> None:
    path = tmp_path / "bridge.db"
    with MappingStore(path) as store:
        original = store.add_mapping(
            provider="agentmail",
            hermes_session="session-1",
            participant_email="person@example.com",
        )
        rotated = store.rotate_mapping_marker(original.id, ttl_days=1)
        assert rotated.bridge_marker != original.bridge_marker
        assert rotated.bridge_marker_expires_at is not None
        assert (
            store.resolve(
                _message(
                    thread_id=None,
                    headers={"X-Hermes-Bridge": f"v1:{original.bridge_marker}"},
                )
            ).status
            is ResolutionStatus.NO_MATCH
        )

    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE mappings SET bridge_marker_expires_at = ? WHERE id = ?",
            ((datetime.now(UTC) - timedelta(days=1)).isoformat(), original.id),
        )
    with MappingStore(path) as store:
        expired = store.resolve(
            _message(
                thread_id=None,
                headers={"X-Hermes-Bridge": f"v1:{rotated.bridge_marker}"},
            )
        )
        assert expired.status is ResolutionStatus.DENIED
        assert expired.matched_by == "expired_bridge_marker"


def test_v0_database_migrates_without_data_loss(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE mappings (
                id INTEGER PRIMARY KEY, provider TEXT NOT NULL, hermes_session TEXT NOT NULL,
                hermes_topic TEXT, provider_thread_id TEXT, subject_key TEXT,
                participant_email TEXT, bridge_marker TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX mappings_provider_thread
                ON mappings(provider, provider_thread_id)
                WHERE provider_thread_id IS NOT NULL;
            INSERT INTO mappings VALUES (
                1, 'agentmail', 'legacy-session', NULL, 'legacy-thread', 'legacy',
                'person@example.com', 'abcdefghijklmnopqrstuvwxyz_123456',
                '2026-07-01T00:00:00+00:00', '2026-07-01T00:00:00+00:00'
            );
            """
        )
    with MappingStore(path) as store:
        mapping = store.list_mappings()[0]
        assert mapping.hermes_session == "legacy-session"
        assert mapping.bridge_marker_expires_at is None
        assert (
            store.resolve(_message(thread_id="legacy-thread")).status is ResolutionStatus.AUTHORIZED
        )
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2


def test_v1_database_with_shared_thread_across_participants_migrates(tmp_path: Path) -> None:
    path = tmp_path / "v1.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE mappings (
                id INTEGER PRIMARY KEY, provider TEXT NOT NULL, hermes_session TEXT NOT NULL,
                hermes_topic TEXT, provider_thread_id TEXT, subject_key TEXT,
                participant_email TEXT, bridge_marker TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                bridge_marker_expires_at TEXT
            );
            CREATE UNIQUE INDEX mappings_provider_thread_participant
                ON mappings(provider, provider_thread_id, participant_email)
                WHERE provider_thread_id IS NOT NULL AND participant_email IS NOT NULL;
            INSERT INTO mappings VALUES
                (1, 'agentmail', 'session-1', NULL, 'shared-thread', NULL,
                 'one@example.test', 'abcdefghijklmnopqrstuvwxyz_123456',
                 '2026-07-01T00:00:00+00:00', '2026-07-01T00:00:00+00:00', NULL),
                (2, 'agentmail', 'session-2', NULL, 'shared-thread', NULL,
                 'two@example.test', 'abcdefghijklmnopqrstuvwxyz_654321',
                 '2026-07-01T00:00:00+00:00', '2026-07-01T00:00:00+00:00', NULL);
            PRAGMA user_version = 1;
            """
        )

    with MappingStore(path) as store:
        assert [item.hermes_session for item in store.list_mappings()] == [
            "session-1",
            "session-2",
        ]
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(mappings)").fetchall()}
        assert "mappings_provider_thread" not in indexes
        assert "mappings_provider_thread_participant" in indexes


def test_rejects_newer_database_version(tmp_path: Path) -> None:
    path = tmp_path / "future.db"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 99")
    with pytest.raises(RuntimeError, match="newer than supported"):
        MappingStore(path)


def test_ongoing_raw_retention_preserves_processed_record_and_secure_new_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state" / "bridge.db"
    old = _message(message_id="old", thread_id=None)
    with MappingStore(path) as store:
        store.mark_processed(old, "done", store_raw=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE processed_messages SET processed_at = ? WHERE message_id = 'old'",
            ((datetime.now(UTC) - timedelta(days=31)).isoformat(),),
        )
    with MappingStore(path) as store:
        store.mark_processed(
            _message(message_id="new", thread_id=None),
            "done",
            store_raw=True,
            raw_retention_days=30,
        )
        assert store.is_processed("agentmail", "old")
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT raw_payload FROM processed_messages WHERE message_id = 'old'"
        ).fetchone() == (None,)
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize(
    "address",
    [
        "not-an-address",
        "@example.test",
        "person@",
        "*@example.test",
        "example.test",
        "Person <person@example.test>",
        "person@example.test\nBcc: attacker@example.test",
    ],
)
def test_allowlist_rejects_non_exact_or_unsafe_addresses(address: str) -> None:
    with MappingStore(":memory:") as store, pytest.raises(ValueError, match="exact"):
        store.add_allowed_address("agentmail", address)


def test_allowlist_is_exact_provider_scoped_and_manually_manageable() -> None:
    with MappingStore(":memory:") as store:
        added = store.add_allowed_address("agentmail", "Person@Example.Test")
        assert added.address == "person@example.test"
        assert added.source == "manual"
        assert store.is_allowed("agentmail", "PERSON@example.test")
        assert not store.is_allowed("fake", "person@example.test")
        assert [entry.address for entry in store.list_allowed_addresses("agentmail")] == [
            "person@example.test"
        ]
        assert store.remove_allowed_address("agentmail", "person@example.test")
        assert not store.remove_allowed_address("agentmail", "person@example.test")
        assert not store.is_allowed("agentmail", "person@example.test")


def test_sent_enrollment_is_idempotent_and_removal_requires_a_new_message() -> None:
    first = SentEmail(
        provider="agentmail",
        provider_message_id="sent-1",
        recipients=("to@example.test", "cc@example.test", "bcc@example.test"),
        sent_at=datetime(2026, 7, 11, 12, tzinfo=UTC),
    )
    second = SentEmail(
        provider="agentmail",
        provider_message_id="sent-2",
        recipients=("to@example.test",),
        sent_at=datetime(2026, 7, 11, 13, tzinfo=UTC),
    )
    unobserved_old = SentEmail(
        provider="agentmail",
        provider_message_id="sent-old-unobserved",
        recipients=("to@example.test",),
        sent_at=datetime(2026, 7, 11, 12, 15, tzinfo=UTC),
    )
    with MappingStore(":memory:") as store:
        assert store.enroll_sent_message(first) == 3
        assert store.enroll_sent_message(first) == 0
        assert store.remove_allowed_address(
            "agentmail",
            "to@example.test",
            now=datetime(2026, 7, 11, 12, 30, tzinfo=UTC),
        )
        assert store.enroll_sent_message(first) == 0
        assert store.enroll_sent_message(unobserved_old) == 0
        assert store.enroll_sent_message(unobserved_old) == 0
        assert not store.is_allowed("agentmail", "to@example.test")
        assert all(
            item.address != "to@example.test" for item in store.list_allowed_addresses("agentmail")
        )
        assert store.enroll_sent_message(second) == 1
        assert store.is_allowed("agentmail", "to@example.test")
        entry = next(
            item
            for item in store.list_allowed_addresses("agentmail")
            if item.address == "to@example.test"
        )
        assert entry.source_message_id == "sent-2"


def test_removing_never_allowed_address_tombstones_old_sent_mail() -> None:
    old = SentEmail(
        provider="agentmail",
        provider_message_id="sent-before-revocation",
        recipients=("person@example.test",),
        sent_at=datetime(2026, 7, 11, 11, tzinfo=UTC),
    )
    with MappingStore(":memory:") as store:
        assert not store.remove_allowed_address(
            "agentmail",
            "person@example.test",
            now=datetime(2026, 7, 11, 12, tzinfo=UTC),
        )
        assert store.enroll_sent_message(old) == 0
        assert not store.is_allowed("agentmail", "person@example.test")
        store.add_allowed_address("agentmail", "person@example.test")
        assert store.is_allowed("agentmail", "person@example.test")


def test_start_now_atomically_seeds_missing_cursors_without_overwrite() -> None:
    start = datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
    with MappingStore(":memory:") as store:
        store.set_cursor("agentmail", "2026-07-10T00:00:00Z")
        assert store.seed_poll_cursors("agentmail", now=start) == ("agentmail:sent",)
        assert store.get_cursor("agentmail") == "2026-07-10T00:00:00Z"
        assert store.get_poll_start("agentmail") is None
        assert store.get_cursor("agentmail:sent") == "2026-07-11T12:00:00Z"
        assert store.get_poll_start("agentmail:sent") == start
        assert store.seed_poll_cursors("agentmail", now=start + timedelta(days=1)) == ()
