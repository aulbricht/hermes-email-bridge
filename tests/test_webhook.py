import base64
import hashlib
import hmac
import http.client
import json
import threading
import time
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer
from typing import Any

import pytest

import hermes_email_bridge.webhook as webhook_module
from hermes_email_bridge.models import (
    ConversationMapping,
    HermesResult,
    NormalizedEmail,
    SenderAuthentication,
)
from hermes_email_bridge.providers.fake import FakeProvider
from hermes_email_bridge.runner import HermesRunner
from hermes_email_bridge.service import BridgeService
from hermes_email_bridge.store import MappingStore
from hermes_email_bridge.webhook import (
    WebhookDispatcher,
    WebhookVerificationError,
    verify_svix,
)


def _headers(payload: bytes, timestamp: int) -> tuple[dict[str, str], str]:
    secret_bytes = b"test-webhook-secret"
    secret = "whsec_" + base64.b64encode(secret_bytes).decode()
    message_id = "msg_123"
    signed = f"{message_id}.{timestamp}.".encode() + payload
    signature = base64.b64encode(hmac.new(secret_bytes, signed, hashlib.sha256).digest()).decode()
    return (
        {
            "svix-id": message_id,
            "svix-timestamp": str(timestamp),
            "svix-signature": f"v1,{signature}",
        },
        secret,
    )


def test_verifies_svix_signature() -> None:
    payload = b'{"event_type":"message.received"}'
    headers, secret = _headers(payload, 1_700_000_000)
    verify_svix(payload, headers, secret, now=1_700_000_001)


def test_rejects_tampered_webhook() -> None:
    payload = b'{"event_type":"message.received"}'
    headers, secret = _headers(payload, 1_700_000_000)
    with pytest.raises(WebhookVerificationError, match="signature"):
        verify_svix(payload + b" ", headers, secret, now=1_700_000_001)


def _message(message_id: str, *, thread_id: str | None = None) -> NormalizedEmail:
    return NormalizedEmail(
        provider="fake",
        provider_message_id=message_id,
        from_email="person@example.com",
        to_email="bridge@example.com",
        subject="Subject",
        text_body="Body",
        received_at=datetime(2026, 7, 10, tzinfo=UTC),
        thread_id=message_id if thread_id is None else thread_id,
        sender_authentication=SenderAuthentication.AUTHENTICATED,
    )


class BlockingRunner(HermesRunner):
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self._lock = threading.Lock()
        self.calls = 0
        self.active = 0
        self.max_active = 0
        self.mappings: list[ConversationMapping | None] = []

    def run(
        self,
        message: NormalizedEmail,
        mapping: ConversationMapping | None,
    ) -> HermesResult:
        with self._lock:
            self.calls += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.mappings.append(mapping)
            self.started.set()
        self.release.wait()
        with self._lock:
            self.active -= 1
        return HermesResult("reply", f"session-{message.provider_message_id}")


def test_webhook_dispatcher_bounds_queue_and_concurrency() -> None:
    messages = [_message(f"message-{index}") for index in range(3)]
    provider = FakeProvider(messages)
    runner = BlockingRunner()
    with MappingStore(":memory:") as store:
        store.add_allowed_address("fake", "person@example.com")
        service = BridgeService(provider=provider, store=store, runner=runner)
        dispatcher = WebhookDispatcher(service, provider, queue_size=1)
        try:
            assert dispatcher.submit({"message_id": "message-0"})
            assert runner.started.wait(timeout=2)
            assert dispatcher.submit({"message_id": "message-1"})
            assert not dispatcher.submit({"message_id": "message-2"})
        finally:
            runner.release.set()
            dispatcher.shutdown()
        assert runner.calls == 2
        assert runner.max_active == 1


def test_same_thread_messages_are_serialized_without_loss() -> None:
    messages = [
        _message("message-1", thread_id="shared-thread"),
        _message("message-2", thread_id="shared-thread"),
    ]
    provider = FakeProvider(messages)
    runner = BlockingRunner()
    with MappingStore(":memory:") as store:
        store.add_allowed_address("fake", "person@example.com")
        service = BridgeService(provider=provider, store=store, runner=runner)
        dispatcher = WebhookDispatcher(service, provider, queue_size=1)
        try:
            assert dispatcher.submit({"message_id": "message-1"})
            assert runner.started.wait(timeout=2)
            assert dispatcher.submit({"message_id": "message-2"})
            assert runner.calls == 1
        finally:
            runner.release.set()
            dispatcher.shutdown()
        assert runner.calls == 2
        assert runner.max_active == 1
        assert runner.mappings[0] is None
        assert runner.mappings[1] is not None
        assert runner.mappings[1].hermes_session == "session-message-1"


def test_webhook_dispatcher_coalesces_in_flight_duplicate() -> None:
    message = _message("message-1")
    provider = FakeProvider([message])
    runner = BlockingRunner()
    with MappingStore(":memory:") as store:
        store.add_allowed_address("fake", "person@example.com")
        service = BridgeService(provider=provider, store=store, runner=runner)
        dispatcher = WebhookDispatcher(service, provider, queue_size=1)
        try:
            assert dispatcher.submit({"message_id": "message-1"})
            assert runner.started.wait(timeout=2)
            assert dispatcher.submit({"message_id": "message-1"})
        finally:
            runner.release.set()
            dispatcher.shutdown()
        assert runner.calls == 1


def test_saturated_webhook_server_returns_503(monkeypatch: pytest.MonkeyPatch) -> None:
    class ThreeRequestServer(ThreadingHTTPServer):
        ready = threading.Event()
        bound_port = 0

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            type(self).bound_port = self.server_port
            type(self).ready.set()

        def serve_forever(self, poll_interval: float = 0.5) -> None:
            for _request in range(3):
                self.handle_request()

    messages = [_message(f"message-{index}") for index in range(3)]
    provider = FakeProvider(messages)
    runner = BlockingRunner()
    errors: list[BaseException] = []
    monkeypatch.setattr(webhook_module, "ThreadingHTTPServer", ThreeRequestServer)

    with MappingStore(":memory:") as store:
        store.add_allowed_address("fake", "person@example.com")
        service = BridgeService(provider=provider, store=store, runner=runner)

        def run_server() -> None:
            try:
                webhook_module.serve_webhooks(
                    service=service,
                    provider=provider,
                    secret=_headers(b"{}", int(time.time()))[1],
                    host="127.0.0.1",
                    port=0,
                    queue_size=1,
                )
            except BaseException as exc:
                errors.append(exc)

        server_thread = threading.Thread(target=run_server)
        server_thread.start()
        try:
            assert ThreeRequestServer.ready.wait(timeout=2)
            statuses = []
            for index in range(3):
                body = json.dumps({"message_id": f"message-{index}"}).encode()
                headers, _secret = _headers(body, int(time.time()))
                connection = http.client.HTTPConnection(
                    "127.0.0.1", ThreeRequestServer.bound_port, timeout=2
                )
                connection.request("POST", "/webhooks", body=body, headers=headers)
                response = connection.getresponse()
                statuses.append(response.status)
                response.read()
                connection.close()
                if index == 0:
                    assert runner.started.wait(timeout=2)
            assert statuses == [204, 204, 503]
        finally:
            runner.release.set()
            server_thread.join(timeout=2)
        assert not server_thread.is_alive()
        assert errors == []
