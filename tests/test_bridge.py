import shlex
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from hermes_email_bridge.models import (
    ConversationMapping,
    HermesResult,
    NormalizedEmail,
    SenderAuthentication,
    SentEmail,
)
from hermes_email_bridge.providers.fake import FakeProvider
from hermes_email_bridge.runner import HermesRunner, SubprocessHermesRunner
from hermes_email_bridge.service import BridgeService
from hermes_email_bridge.store import MappingStore


def _message() -> NormalizedEmail:
    return NormalizedEmail(
        provider="fake",
        provider_message_id="message-1",
        from_email="person@example.com",
        to_email="bridge@example.com",
        subject="A topic",
        text_body="Hello from email",
        received_at=datetime(2026, 7, 9, tzinfo=UTC),
        thread_id="thread-1",
        raw_payload={"message_id": "message-1", "text": "Hello from email"},
        sender_authentication=SenderAuthentication.AUTHENTICATED,
    )


class StubRunner(HermesRunner):
    def __init__(self) -> None:
        self.calls = 0

    def run(
        self,
        message: NormalizedEmail,
        mapping: ConversationMapping | None,
    ) -> HermesResult:
        self.calls += 1
        return HermesResult("Hermes reply", mapping.hermes_session if mapping else "session-new")


def test_dry_run_never_sends_reply() -> None:
    message = _message()
    provider = FakeProvider([message])
    with MappingStore(":memory:") as store:
        store.add_allowed_address("fake", "person@example.com")
        service = BridgeService(
            provider=provider,
            store=store,
            runner=StubRunner(),
            send_replies=True,
            dry_run=True,
        )
        summary = service.poll_once()

        assert summary.processed == 1
        assert provider.replies == []
        assert store.is_processed("fake", "message-1")
        assert store.resolve(message).mapping is not None


def test_unauthenticated_message_never_invokes_hermes_or_changes_mapping() -> None:
    authenticated = _message()
    message = replace(
        authenticated,
        sender_authentication=SenderAuthentication.UNAUTHENTICATED,
    )
    provider = FakeProvider([message])
    runner = StubRunner()
    with MappingStore(":memory:") as store:
        store.add_allowed_address("fake", "person@example.com")
        original = store.add_mapping(
            provider="fake",
            hermes_session="existing-session",
            provider_thread_id="thread-1",
            participant_email="person@example.com",
        )
        service = BridgeService(provider=provider, store=store, runner=runner)

        assert service.handle(message) == "skipped"
        assert runner.calls == 0
        assert provider.replies == []
        assert store.list_mappings() == [original]


def test_authenticated_unallowlisted_message_never_invokes_maps_or_replies() -> None:
    message = _message()
    provider = FakeProvider([message])
    runner = StubRunner()
    with MappingStore(":memory:") as store:
        service = BridgeService(
            provider=provider,
            store=store,
            runner=runner,
            send_replies=True,
            dry_run=False,
            store_raw=True,
        )
        assert service.handle(message) == "skipped"
        assert runner.calls == 0
        assert store.list_mappings() == []
        assert provider.replies == []
        raw = store._connection.execute(
            "SELECT raw_payload FROM processed_messages WHERE message_id = 'message-1'"
        ).fetchone()
        assert raw is not None and raw[0] is None


def test_allowlisted_but_unauthenticated_message_still_fails_closed() -> None:
    message = replace(_message(), sender_authentication=SenderAuthentication.UNAUTHENTICATED)
    provider = FakeProvider([message])
    runner = StubRunner()
    with MappingStore(":memory:") as store:
        store.add_allowed_address("fake", message.from_email)
        service = BridgeService(
            provider=provider,
            store=store,
            runner=runner,
            send_replies=True,
            dry_run=False,
        )
        assert service.handle(message) == "skipped"
        assert runner.calls == 0
        assert provider.replies == []


def test_trusted_sent_enrollment_precedes_inbound_and_replies_exactly_once() -> None:
    message = _message()
    sent = SentEmail(
        provider="fake",
        provider_message_id="sent-1",
        recipients=(message.from_email,),
        sent_at=message.received_at - timedelta(minutes=1),
    )
    provider = FakeProvider([message], [sent])
    runner = StubRunner()
    with MappingStore(":memory:") as store:
        service = BridgeService(
            provider=provider,
            store=store,
            runner=runner,
            send_replies=True,
            dry_run=False,
        )
        summary = service.poll_once()
        assert summary.processed == 1
        assert runner.calls == 1
        assert provider.replies == [("message-1", "Hermes reply")]
        assert store.is_allowed("fake", message.from_email)
        assert service.poll_once().skipped == 1
        assert runner.calls == 1
        assert len(provider.replies) == 1


def test_start_now_ignores_historical_sent_and_inbound_messages() -> None:
    start = datetime(2026, 7, 9, 1, tzinfo=UTC)
    inbound = _message()
    sent = SentEmail(
        provider="fake",
        provider_message_id="sent-before-start",
        recipients=(inbound.from_email,),
        sent_at=inbound.received_at,
    )
    provider = FakeProvider([inbound], [sent])
    runner = StubRunner()
    with MappingStore(":memory:") as store:
        store.seed_poll_cursors("fake", now=start)
        service = BridgeService(provider=provider, store=store, runner=runner)
        summary = service.poll_once()
        assert summary.skipped == 1
        assert runner.calls == 0
        assert not store.is_allowed("fake", inbound.from_email)


def test_fake_provider_contract() -> None:
    message = _message()
    provider = FakeProvider([message])

    assert provider.poll(None).messages == (message,)
    assert provider.get("message-1") == message
    assert provider.reply(message, "reply") == "fake-reply-1"
    assert provider.replies == [("message-1", "reply")]


def test_subprocess_runner_uses_prompt_and_captures_session() -> None:
    script = "import sys; print(sys.argv[-1]); print('session_id: session-new', file=sys.stderr)"
    command = shlex.join([sys.executable, "-c", script])
    result = SubprocessHermesRunner(command).run(_message(), None)

    assert "Hello from email" in result.reply
    assert "UNTRUSTED EMAIL USER CONTENT" in result.reply
    assert result.session_id == "session-new"
