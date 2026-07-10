import shlex
import sys
from dataclasses import replace
from datetime import UTC, datetime

from hermes_email_bridge.models import (
    ConversationMapping,
    HermesResult,
    NormalizedEmail,
    SenderAuthentication,
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
