from datetime import UTC, datetime
from pathlib import Path

from hermes_email_bridge.models import NormalizedEmail
from hermes_email_bridge.store import MappingStore


def _message(
    *,
    message_id: str = "<inbound@example.com>",
    in_reply_to: str | None = None,
    references: tuple[str, ...] = (),
    headers: dict[str, str] | None = None,
    thread_id: str | None = "thread-1",
) -> NormalizedEmail:
    return NormalizedEmail(
        provider="agentmail",
        provider_message_id=message_id,
        from_email="person@example.com",
        to_email="bridge@agentmail.to",
        subject="Re: Project Atlas",
        text_body="reply",
        received_at=datetime(2026, 7, 9, tzinfo=UTC),
        in_reply_to=in_reply_to,
        references=references,
        thread_id=thread_id,
        raw_payload={"headers": headers or {}},
    )


def test_resolves_in_reply_to_and_references(tmp_path: Path) -> None:
    with MappingStore(tmp_path / "bridge.db") as store:
        mapping = store.add_mapping(
            provider="agentmail",
            hermes_session="session-1",
            provider_thread_id="original-thread",
            subject="Project Atlas",
            participant_email="person@example.com",
            message_ids=("<outbound@example.com>",),
        )
        by_reply = store.resolve(
            _message(in_reply_to="<outbound@example.com>", thread_id="new-thread")
        )
        by_reference = store.resolve(
            _message(
                message_id="<second@example.com>",
                references=("<old@example.com>", "<outbound@example.com>"),
                thread_id="new-thread",
            )
        )

        assert by_reply and by_reply.mapping.id == mapping.id
        assert by_reply.matched_by == "in_reply_to"
        assert by_reference and by_reference.mapping.id == mapping.id
        assert by_reference.matched_by == "references"


def test_extracts_opaque_bridge_marker(tmp_path: Path) -> None:
    with MappingStore(tmp_path / "bridge.db") as store:
        mapping = store.add_mapping(
            provider="agentmail",
            hermes_session="session-2",
            bridge_marker="abcdefghijklmnopqrstuvwxyz_123456",
        )
        resolved = store.resolve(
            _message(
                thread_id=None,
                headers={"X-Hermes-Bridge": "v1:abcdefghijklmnopqrstuvwxyz_123456"},
            )
        )
        forged_body = _message(thread_id=None, headers={})

        assert resolved and resolved.mapping.id == mapping.id
        assert resolved.matched_by == "bridge_marker"
        assert store.resolve(forged_body) is None


def test_sqlite_mapping_persists(tmp_path: Path) -> None:
    path = tmp_path / "bridge.db"
    with MappingStore(path) as store:
        store.add_mapping(
            provider="agentmail",
            hermes_session="persisted-session",
            provider_thread_id="persisted-thread",
        )

    with MappingStore(path) as reopened:
        mappings = reopened.list_mappings()
        assert len(mappings) == 1
        assert mappings[0].hermes_session == "persisted-session"
        assert reopened.resolve(_message(thread_id="persisted-thread")) is not None
