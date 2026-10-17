"""Import routing is opt-in, authorized, and durable across process restarts."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hermes_email_bridge.import_handoff import AttachmentReader
from hermes_email_bridge.models import (
    Attachment,
    ConversationMapping,
    HermesResult,
    NormalizedEmail,
    SenderAuthentication,
)
from hermes_email_bridge.providers.base import AmbiguousSendError
from hermes_email_bridge.providers.fake import FakeProvider
from hermes_email_bridge.runner import HermesRunner
from hermes_email_bridge.service import BridgeService
from hermes_email_bridge.store import MappingStore


class Provider(FakeProvider):
    name = "nylas"
    requires_reply_proof = True

    def download_attachment(
        self, message: NormalizedEmail, attachment: Attachment, *, max_bytes: int
    ) -> bytes:
        assert message.sender_authentication is SenderAuthentication.AUTHENTICATED
        assert attachment in message.attachments and max_bytes == 1024
        return b"%PDF"


class Runner(HermesRunner):
    def __init__(self) -> None:
        self.calls = 0

    def run(self, message: NormalizedEmail, mapping: ConversationMapping | None) -> HermesResult:
        self.calls += 1
        return HermesResult("generic", "session")


class Handoff:
    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[str] = []
        self.fail = fail

    def wants(self, message: NormalizedEmail, mapping: ConversationMapping | None) -> bool:
        return bool(message.attachments)

    def handle(
        self,
        message: NormalizedEmail,
        mapping: ConversationMapping | None,
        read_attachment: AttachmentReader,
        operation_id: str,
    ) -> str:
        self.calls.append(operation_id)
        if self.fail:
            raise RuntimeError("dispatch outcome unknown")
        if message.attachments:
            assert read_attachment(message.attachments[0], 1024) == b"%PDF"
        return "Import received for review"


def message(message_id: str = "message-1", *, attachment: bool = True) -> NormalizedEmail:
    return NormalizedEmail(
        provider="nylas",
        provider_message_id=message_id,
        from_email="owner@example.test",
        to_email="agent@example.test",
        subject="Import",
        text_body="Please import",
        received_at=datetime(2026, 10, 17, tzinfo=UTC),
        thread_id="thread-1",
        sender_authentication=SenderAuthentication.AUTHENTICATED,
        attachments=(Attachment("attachment-1", "rent.pdf", "application/pdf", 12),)
        if attachment
        else (),
    )


def service(
    store: MappingStore, provider: Provider, runner: Runner, handoff: Handoff
) -> BridgeService:
    return BridgeService(
        provider=provider,
        store=store,
        runner=runner,
        import_handoff=handoff,
        send_replies=True,
        dry_run=False,
        allowed_senders=frozenset({"owner@example.test"}),
    )


def test_import_claim_and_reply_are_not_repeated_after_reload(tmp_path: Path) -> None:
    db = tmp_path / "bridge.db"
    provider, runner, handoff = Provider([]), Runner(), Handoff()
    with MappingStore(db) as store:
        bridge = service(store, provider, runner, handoff)
        assert bridge.handle(message()) == "processed"
        assert bridge.handle(message()) == "skipped"
    with MappingStore(db) as store:
        bridge = service(store, provider, runner, handoff)
        assert bridge.handle(message()) == "skipped"
        assert bridge.handle(message("message-2", attachment=False)) == "processed"
        rows = store._connection.execute(
            "SELECT message_id,state,attachment_ids_json FROM import_email_messages "
            "ORDER BY message_id"
        ).fetchall()
        assert [(row["message_id"], row["state"]) for row in rows] == [
            ("message-1", "reply_sent"),
            ("message-2", "reply_sent"),
        ]
        assert rows[0]["attachment_ids_json"] == '["attachment-1"]'
        assert rows[1]["attachment_ids_json"] == "[]"
    assert len(handoff.calls) == 2
    assert len(set(handoff.calls)) == 2
    assert runner.calls == 0
    assert len(provider.replies) == 2


def test_unknown_or_unallowlisted_sender_cannot_reach_import(tmp_path: Path) -> None:
    provider, runner, handoff = Provider([]), Runner(), Handoff()
    with MappingStore(tmp_path / "bridge.db") as store:
        bridge = service(store, provider, runner, handoff)
        unknown = replace(message(), sender_authentication=SenderAuthentication.UNKNOWN)
        other = replace(message("message-2"), from_email="other@example.test")
        assert bridge.handle(unknown) == "skipped"
        assert bridge.handle(other) == "skipped"
        assert store.import_thread_owner("nylas", "thread-1") is None
    assert handoff.calls == [] and runner.calls == 0 and provider.replies == []


def test_reply_proof_cannot_start_a_fresh_import(tmp_path: Path) -> None:
    provider, runner, handoff = Provider([]), Runner(), Handoff()
    with MappingStore(tmp_path / "bridge.db") as store:
        bridge = service(store, provider, runner, handoff)
        proven = replace(message(), sender_authentication=SenderAuthentication.REPLY_PROVEN)
        assert bridge.handle(proven) == "processed"
        assert store.import_thread_owner("nylas", "thread-1") is None
    assert handoff.calls == [] and runner.calls == 1


def test_interrupted_handoff_stops_for_reconciliation_after_reload(tmp_path: Path) -> None:
    db = tmp_path / "bridge.db"
    provider, runner, handoff = Provider([]), Runner(), Handoff(fail=True)
    with MappingStore(db) as store:
        assert service(store, provider, runner, handoff).handle(message()) == "processed"
    with MappingStore(db) as store:
        assert service(store, provider, runner, handoff).handle(message()) == "skipped"
        row = store._connection.execute("SELECT state FROM import_email_messages").fetchone()
        assert row and row["state"] == "failed"
    assert len(handoff.calls) == 1
    assert runner.calls == 0 and provider.replies == []


def test_existing_import_thread_cannot_fall_back_to_generic_runner(tmp_path: Path) -> None:
    db = tmp_path / "bridge.db"
    provider, runner, handoff = Provider([]), Runner(), Handoff()
    with MappingStore(db) as store:
        assert service(store, provider, runner, handoff).handle(message()) == "processed"
    with MappingStore(db) as store:
        paused = BridgeService(
                provider=provider, store=store, runner=runner, send_replies=False, dry_run=True,
                allowed_senders=frozenset({"owner@example.test"}),
        )
        with pytest.raises(RuntimeError, match="import route is paused"):
            paused.handle(message("message-2", attachment=False))
        assert not store.is_processed("nylas", "message-2")
    assert runner.calls == 0 and len(provider.replies) == 1


def test_uncertain_import_reply_has_durable_send_intent_and_no_replay(tmp_path: Path) -> None:
    db = tmp_path / "bridge.db"
    runner, handoff = Runner(), Handoff()
    class UncertainProvider(Provider):
        store = None
        sends = 0

        def reply(self, email, text):
            self.sends += 1
            row = self.store._connection.execute(
                "SELECT state FROM import_email_messages WHERE message_id=?",
                (email.provider_message_id,),
            ).fetchone()
            assert row["state"] == "handled"  # Durable intent precedes provider send.
            raise AmbiguousSendError("send outcome unknown")

    provider = UncertainProvider([])
    with MappingStore(db) as store:
        provider.store = store
        bridge = service(store, provider, runner, handoff)
        assert bridge.handle(message()) == "processed"
        assert bridge.handle(message()) == "skipped"
        assert store._connection.execute(
            "SELECT state FROM import_email_messages WHERE message_id='message-1'"
        ).fetchone()["state"] == "reply_uncertain"
    with MappingStore(db) as store:
        provider.store = store
        assert service(store, provider, runner, handoff).handle(message()) == "skipped"
    assert provider.sends == 1 and len(handoff.calls) == 1 and runner.calls == 0
