import json
import logging
import os
import shlex
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from hermes_email_bridge.models import (
    ConversationMapping,
    HermesAction,
    HermesResult,
    NormalizedEmail,
    SenderAuthentication,
    SentEmail,
)
from hermes_email_bridge.providers.fake import FakeProvider
from hermes_email_bridge.runner import (
    HERMES_PROTOCOL,
    HermesProtocolError,
    HermesRunner,
    SubprocessHermesRunner,
    parse_hermes_protocol,
)
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


@pytest.mark.parametrize(
    ("sender", "reply_expected"),
    [
        ("person@example.com", True),
        ("person@sub.example.com", False),
        ("person@evil-example.com", False),
    ],
)
def test_reply_domain_gate_requires_an_exact_domain(sender: str, reply_expected: bool) -> None:
    message = replace(_message(), from_email=sender)
    provider = FakeProvider([message])
    runner = StubRunner()
    with MappingStore(":memory:") as store:
        store.add_allowed_address("fake", sender)
        service = BridgeService(
            provider=provider,
            store=store,
            runner=runner,
            send_replies=True,
            dry_run=False,
            reply_domains=frozenset({"example.com"}),
        )

        assert service.handle(message) == "processed"
        assert runner.calls == 1
        assert bool(provider.replies) is reply_expected


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


def _protocol_script(reply_expression: str = "sys.argv[-1]") -> str:
    return (
        "import json,sys; "
        f"reply={reply_expression}; "
        "print(json.dumps({'action':'reply','protocol':'hermes-email-bridge/2','reply':reply,"
        "'session_id':'session-new'},sort_keys=True,ensure_ascii=False,separators=(',',':')))"
    )


def test_subprocess_runner_uses_prompt_and_captures_session() -> None:
    script = _protocol_script(
        "'Clean reply' if 'UNTRUSTED EMAIL USER CONTENT' in sys.argv[-1] else ''"
    )
    command = shlex.join([sys.executable, "-c", script])
    result = SubprocessHermesRunner(command).run(_message(), None)

    assert result.reply == "Clean reply"
    assert result.session_id == "session-new"


def test_subprocess_runner_passes_only_minimal_execution_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forbidden_names = (
        "EMAIL_BRIDGE_ENV_FILE",
        "EMAIL_BRIDGE_COMPOSIO_API_KEY",
        "COMPOSIO_API_KEY",
        "AGENTMAIL_API_KEY",
        "AGENTMAIL_WEBHOOK_SECRET",
        "EMAIL_BRIDGE_DB_PATH",
        "HERMES_HOME",
        "HOME",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "PYTHONPATH",
        "ARBITRARY_PARENT_SENTINEL",
    )
    for index, name in enumerate(forbidden_names):
        monkeypatch.setenv(name, f"parent-only-{index}")
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    child_reply = (
        f"json.dumps({{name: os.getenv(name) for name in {forbidden_names!r}}} | "
        "{'PATH': os.getenv('PATH'), 'LANG': os.getenv('LANG'), "
        "'ENV_KEYS': sorted(os.environ), 'CWD': os.getcwd()},sort_keys=True)"
    )
    script = "import os; " + _protocol_script(child_reply)
    command = shlex.join([sys.executable, "-c", script])
    result = SubprocessHermesRunner(command).run(_message(), None)
    child_env = json.loads(result.reply)

    assert all(child_env[name] is None for name in forbidden_names)
    assert child_env["PATH"] == os.environ["PATH"]
    assert child_env["LANG"] == "en_US.UTF-8"
    assert child_env["CWD"] == os.path.abspath(os.sep)
    # macOS may synthesize this Cocoa text-encoding variable after execve.
    assert set(child_env["ENV_KEYS"]) <= {
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "__CF_USER_TEXT_ENCODING",
    }


def _record(
    reply: str = "Short final answer.",
    session_id: str = "session_123",
    action: str = "reply",
) -> bytes:
    return (
        json.dumps(
            {
                "action": action,
                "protocol": HERMES_PROTOCOL,
                "reply": reply,
                "session_id": session_id,
            },
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def test_protocol_accepts_only_clean_canonical_final_response() -> None:
    result = parse_hermes_protocol(_record("Hello.\n\nThis is the final answer."), b"", 0)
    assert result == HermesResult("Hello.\n\nThis is the final answer.", "session_123")


def test_protocol_accepts_only_declared_actions() -> None:
    result = parse_hermes_protocol(_record(action="approval_required"), b"", 0)
    assert result.action is HermesAction.APPROVAL_REQUIRED
    with pytest.raises(HermesProtocolError) as rejected:
        parse_hermes_protocol(_record(action="run_tools"), b"", 0)
    assert rejected.value.code == "invalid_action"


@pytest.mark.parametrize(
    ("stdout", "stderr", "returncode"),
    [
        (b"Reasoning panel\n" + _record(), b"", 0),
        (b"tool preview\n" + _record(), b"", 0),
        (b"timeout\n" + _record(), b"", 0),
        (_record() + _record(), b"", 0),
        (b"\x1b[31m" + _record(), b"", 0),
        (_record(), b"terminal warning", 0),
        (_record(), b"", 1),
        (b"{}\n", b"", 0),
        (b'{"protocol":"wrong/1","reply":"ok","session_id":"s"}\n', b"", 0),
        (b'{"protocol":"hermes-email-bridge/1","session_id":"s"}\n', b"", 0),
        (b'{"protocol":"hermes-email-bridge/1","reply":1,"session_id":"s"}\n', b"", 0),
        (b'{"protocol":"hermes-email-bridge/1","reply":"ok","session_id":"../s"}\n', b"", 0),
        (b'{"protocol":"hermes-email-bridge/1","reply":"ok","session_id":"s","x":1}\n', b"", 0),
        (
            b'{"protocol":"hermes-email-bridge/1","reply":"ok","reply":"again","session_id":"s"}\n',
            b"",
            0,
        ),
        (_record() + b"\n", b"", 0),
        (b"\xef\xbb\xbf" + _record(), b"", 0),
        (_record("\x1b[31manswer\x1b[0m"), b"", 0),
        (_record("┌─ Reasoning ─┐"), b"", 0),
        (_record("[TRUSTED METADATA]\nsecret"), b"", 0),
    ],
)
def test_protocol_rejects_contamination_and_malformed_output(
    stdout: bytes, stderr: bytes, returncode: int
) -> None:
    with pytest.raises(HermesProtocolError):
        parse_hermes_protocol(stdout, stderr, returncode)


def test_incident_transcript_raw_replay_is_rejected() -> None:
    fixture = Path(__file__).with_name("fixtures") / "incident_terminal_transcript.txt"
    contaminated = fixture.read_text().replace("␛", "\x1b").encode()
    with pytest.raises(HermesProtocolError) as rejected:
        parse_hermes_protocol(contaminated, b"", 0)
    assert rejected.value.__context__ is None
    assert "synthetic-message" not in str(rejected.value)


def test_incident_transcript_replay_marks_processed_and_sends_no_email() -> None:
    fixture = Path(__file__).with_name("fixtures") / "incident_terminal_transcript.txt"
    script = f"import sys;sys.stdout.buffer.write(open({str(fixture)!r},'rb').read())"
    message = _message()
    provider = FakeProvider([message])
    with MappingStore(":memory:") as store:
        store.add_allowed_address("fake", message.from_email)
        service = BridgeService(
            provider=provider,
            store=store,
            runner=SubprocessHermesRunner(shlex.join([sys.executable, "-c", script])),
            send_replies=True,
            dry_run=False,
        )
        assert service.handle(message) == "processed"
        assert provider.replies == []
        assert store.list_mappings() == []


def test_subprocess_capture_is_bounded_and_timeout_fails_closed() -> None:
    oversized = shlex.join([sys.executable, "-c", "import os;os.write(1,b'x'*300000)"])
    with pytest.raises(HermesProtocolError) as too_large:
        SubprocessHermesRunner(oversized).run(_message(), None)
    assert too_large.value.code == "output_too_large"

    slow = shlex.join([sys.executable, "-c", "import time;time.sleep(1)"])
    with pytest.raises(HermesProtocolError) as timed_out:
        SubprocessHermesRunner(slow, timeout=0.01).run(_message(), None)
    assert timed_out.value.code == "timeout"


class ProtocolFailureRunner(HermesRunner):
    def run(
        self,
        message: NormalizedEmail,
        mapping: ConversationMapping | None,
    ) -> HermesResult:
        raise HermesProtocolError("malformed_json")


def test_protocol_failure_is_redacted_processed_once_and_never_delivered(
    caplog: pytest.LogCaptureFixture,
) -> None:
    fixture_text = (
        Path(__file__).with_name("fixtures") / "incident_terminal_transcript.txt"
    ).read_text()
    message = replace(_message(), provider_message_id="SENSITIVE-MESSAGE-ID")
    provider = FakeProvider([message])
    secret = "SECRET-CANARY-MUST-NOT-LOG"
    contaminated = replace(
        message,
        text_body=f"{fixture_text}\n{secret}",
        raw_payload={"secret": secret, "incident": fixture_text},
    )
    with MappingStore(":memory:") as store:
        store.add_allowed_address("fake", contaminated.from_email)
        original = store.add_mapping(
            provider="fake",
            hermes_session="existing-session",
            provider_thread_id=contaminated.thread_id,
            participant_email=contaminated.from_email,
        )
        service = BridgeService(
            provider=provider,
            store=store,
            runner=ProtocolFailureRunner(),
            send_replies=True,
            dry_run=False,
        )
        with caplog.at_level(logging.WARNING):
            assert service.handle(contaminated) == "processed"
        row = store._connection.execute(
            "SELECT outcome, raw_payload FROM processed_messages WHERE message_id = ?",
            (contaminated.provider_message_id,),
        ).fetchone()
        assert tuple(row) == ("hermes_protocol_error", None)
        assert service.handle(contaminated) == "skipped"
        assert provider.replies == []
        assert store.list_mappings() == [original]
        assert (
            store._connection.execute(
                "SELECT 1 FROM message_links WHERE message_id = ?",
                (contaminated.provider_message_id,),
            ).fetchone()
            is None
        )
        record = caplog.records[-1]
        record_state = repr(record.__dict__)
        for forbidden in (
            contaminated.provider_message_id,
            contaminated.text_body,
            "Reasoning",
            "Tool Preview",
            "Hello Casey",
            secret,
        ):
            assert forbidden not in caplog.text
            assert forbidden not in record.getMessage()
            assert forbidden not in record_state
        assert record.getMessage() == "Hermes protocol rejected"
        assert record.__dict__["event"] == "hermes_protocol_error"
        assert record.__dict__["reason"] == "malformed_json"
        assert "provider" not in record.__dict__
        assert "provider_message_id" not in record.__dict__


def test_oversized_json_integer_is_redacted_processed_once_and_never_delivered(
    caplog: pytest.LogCaptureFixture,
) -> None:
    huge_integer = "9" * 5000
    raw = (
        f'{{"protocol":{huge_integer},"reply":"must not send","session_id":"session_123"}}\n'
    ).encode()
    with pytest.raises(HermesProtocolError) as rejected:
        parse_hermes_protocol(raw, b"", 0)
    assert rejected.value.code == "malformed_json"

    message = _message()
    provider = FakeProvider([message])
    script = f"import os;os.write(1,{raw!r})"
    with MappingStore(":memory:") as store:
        store.add_allowed_address("fake", message.from_email)
        service = BridgeService(
            provider=provider,
            store=store,
            runner=SubprocessHermesRunner(shlex.join([sys.executable, "-c", script])),
            send_replies=True,
            dry_run=False,
        )
        with caplog.at_level(logging.WARNING):
            assert service.handle(message) == "processed"
        assert service.handle(message) == "skipped"
        assert provider.replies == []
        assert store.list_mappings() == []
        assert huge_integer[:100] not in caplog.text
        assert caplog.records[-1].__dict__["reason"] == "malformed_json"


def test_resumed_session_may_rotate_and_preserves_threaded_reply() -> None:
    message = _message()
    provider = FakeProvider([message])

    class RotatingRunner(HermesRunner):
        def run(
            self,
            message: NormalizedEmail,
            mapping: ConversationMapping | None,
        ) -> HermesResult:
            assert mapping is not None and mapping.hermes_session == "session-old"
            return HermesResult("Rotated reply", "session-rotated")

    with MappingStore(":memory:") as store:
        store.add_allowed_address("fake", message.from_email)
        store.add_mapping(
            provider="fake",
            hermes_session="session-old",
            provider_thread_id=message.thread_id,
            participant_email=message.from_email,
        )
        service = BridgeService(
            provider=provider,
            store=store,
            runner=RotatingRunner(),
            send_replies=True,
            dry_run=False,
        )
        assert service.handle(message) == "processed"
        assert store.list_mappings()[0].hermes_session == "session-rotated"
        assert provider.replies == [(message.provider_message_id, "Rotated reply")]


def test_end_to_end_delivered_body_exactly_equals_protocol_reply() -> None:
    expected = "Hello.\n\nOnly this short answer is delivered."
    command = shlex.join([sys.executable, "-c", _protocol_script(repr(expected))])
    message = _message()
    provider = FakeProvider([message])
    with MappingStore(":memory:") as store:
        store.add_allowed_address("fake", message.from_email)
        service = BridgeService(
            provider=provider,
            store=store,
            runner=SubprocessHermesRunner(command),
            send_replies=True,
            dry_run=False,
        )
        assert service.handle(message) == "processed"
        assert provider.replies == [(message.provider_message_id, expected)]


def test_subprocess_command_preflight_runs_immediately_before_each_invocation() -> None:
    expected = "Preflight passed."
    command = shlex.join([sys.executable, "-c", _protocol_script(repr(expected))])
    calls: list[str] = []
    runner = SubprocessHermesRunner(command, command_preflight=lambda: calls.append("checked"))

    assert runner.run(_message(), None).reply == expected
    assert runner.run(_message(), None).reply == expected
    assert calls == ["checked", "checked"]


def test_tool_request_is_queued_before_acknowledgment() -> None:
    message = _message()
    events: list[str] = []

    class ApprovalRunner(HermesRunner):
        def run(
            self,
            message: NormalizedEmail,
            mapping: ConversationMapping | None,
        ) -> HermesResult:
            return HermesResult(
                "I queued this for approval.",
                "approval-session",
                HermesAction.APPROVAL_REQUIRED,
            )

    with MappingStore(":memory:") as store:
        class OrderedProvider(FakeProvider):
            def reply(self, inbound: NormalizedEmail, text: str) -> str:
                assert len(store.list_approvals("fake")) == 1
                events.append("replied")
                return super().reply(inbound, text)

        provider = OrderedProvider([message])
        store.add_allowed_address("fake", message.from_email)
        service = BridgeService(
            provider=provider,
            store=store,
            runner=ApprovalRunner(),
            send_replies=True,
            dry_run=False,
        )
        assert service.handle(message) == "processed"
        assert events == ["replied"]
        approval = store.list_approvals("fake")[0]
        assert approval.provider_message_id == message.provider_message_id
        assert approval.hermes_session == "approval-session"
        assert provider.replies == [(message.provider_message_id, "I queued this for approval.")]


def test_interrupted_approval_ack_retry_updates_one_pending_session() -> None:
    message = _message()

    class InterruptOnceProvider(FakeProvider):
        def __init__(self) -> None:
            super().__init__([message])
            self.interrupted = False

        def reply(self, inbound: NormalizedEmail, text: str) -> str:
            if not self.interrupted:
                self.interrupted = True
                raise KeyboardInterrupt
            return super().reply(inbound, text)

    class RotatingApprovalRunner(HermesRunner):
        def run(
            self,
            message: NormalizedEmail,
            mapping: ConversationMapping | None,
        ) -> HermesResult:
            session = "approval-first" if mapping is None else "approval-retried"
            return HermesResult(
                "Queued for human review.", session, HermesAction.APPROVAL_REQUIRED
            )

    provider = InterruptOnceProvider()
    with MappingStore(":memory:") as store:
        store.add_allowed_address("fake", message.from_email)
        service = BridgeService(
            provider=provider,
            store=store,
            runner=RotatingApprovalRunner(),
            send_replies=True,
            dry_run=False,
        )
        with pytest.raises(KeyboardInterrupt):
            service.handle(message)
        assert not store.is_processed("fake", message.provider_message_id)
        assert store.list_approvals("fake")[0].hermes_session == "approval-first"

        assert service.handle(message) == "processed"
        approvals = store.list_approvals("fake")
        assert len(approvals) == 1
        assert approvals[0].hermes_session == "approval-retried"
        assert provider.replies == [
            (message.provider_message_id, "Queued for human review.")
        ]


@pytest.mark.parametrize(
    ("send_replies", "dry_run"),
    [(False, False), (True, True)],
)
def test_tool_request_does_not_mutate_approval_queue_in_safe_modes(
    send_replies: bool, dry_run: bool
) -> None:
    message = _message()
    provider = FakeProvider([message])

    class ApprovalRunner(HermesRunner):
        def run(
            self,
            message: NormalizedEmail,
            mapping: ConversationMapping | None,
        ) -> HermesResult:
            return HermesResult("Must not send", "session-new", HermesAction.APPROVAL_REQUIRED)

    with MappingStore(":memory:") as store:
        store.add_allowed_address("fake", message.from_email)
        service = BridgeService(
            provider=provider,
            store=store,
            runner=ApprovalRunner(),
            send_replies=send_replies,
            dry_run=dry_run,
        )
        assert service.handle(message) == "processed"
        assert provider.replies == []
        assert store.list_approvals("fake") == []
