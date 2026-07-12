from __future__ import annotations

import io
import json
import threading
import traceback
from datetime import UTC, datetime
from email.message import Message
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request

import pytest

import hermes_email_bridge.providers.composio_agentmail as composio_module
from hermes_email_bridge.models import NormalizedEmail, SenderAuthentication
from hermes_email_bridge.providers.base import RetryableProviderError
from hermes_email_bridge.providers.composio_agentmail import (
    ComposioAgentMailError,
    ComposioAgentMailProvider,
)


class Response:
    def __init__(self, payload: Any) -> None:
        self.payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode()

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *_args: object) -> None:
        pass

    def read(self) -> bytes:
        return self.payload


class CapturingOpener:
    def __init__(self, payload: Any) -> None:
        self.payload = payload
        self.requests: list[Request] = []

    def open(self, request: Request, timeout: float) -> Response:
        self.requests.append(request)
        return Response(self.payload)


class QueueOpener(CapturingOpener):
    def __init__(self, payloads: list[Any]) -> None:
        super().__init__(None)
        self.payloads = payloads

    def open(self, request: Request, timeout: float) -> Response:
        self.requests.append(request)
        return Response(self.payloads.pop(0))


def _provider(payload: Any) -> tuple[ComposioAgentMailProvider, CapturingOpener]:
    provider = ComposioAgentMailProvider(
        api_key="composio-test-key",
        connected_account_id="ca_test",
        inbox_id="bridge@agentmail.test",
    )
    opener = CapturingOpener(payload)
    provider._opener = opener  # type: ignore[assignment]
    return provider, opener


def test_proxy_wraps_fixed_agentmail_path_and_multivalue_query() -> None:
    provider, opener = _provider({"status": 200, "data": {"messages": []}, "headers": {}})

    assert provider._request(
        "GET",
        "/inboxes/bridge%40agentmail.test/messages",
        params={"labels": ["sent", "received"], "limit": 100},
    ) == {"messages": []}

    request = opener.requests[0]
    assert request.full_url == "https://backend.composio.dev/api/v3.1/tools/execute/proxy"
    assert request.get_header("X-api-key") == "composio-test-key"
    assert isinstance(request.data, bytes)
    wrapped = json.loads(request.data)
    assert wrapped == {
        "connected_account_id": "ca_test",
        "endpoint": "/v0/inboxes/bridge%40agentmail.test/messages",
        "method": "GET",
        "parameters": [
            {"in": "query", "name": "labels", "value": "sent"},
            {"in": "query", "name": "labels", "value": "received"},
            {"in": "query", "name": "limit", "value": "100"},
        ],
    }


def test_threaded_reply_uses_only_fixed_relative_endpoint_and_body() -> None:
    provider, opener = _provider({"status": 200, "data": {"message_id": "reply-1"}})
    inbound = NormalizedEmail(
        provider="agentmail",
        provider_message_id="<inbound@example.test>",
        from_email="person@example.test",
        to_email="bridge@agentmail.test",
        subject="subject",
        text_body="body",
        received_at=datetime(2026, 7, 11, tzinfo=UTC),
        sender_authentication=SenderAuthentication.AUTHENTICATED,
    )
    assert provider.reply(inbound, "reply") == "reply-1"
    assert isinstance(opener.requests[0].data, bytes)
    wrapped = json.loads(opener.requests[0].data)
    assert wrapped["endpoint"] == (
        "/v0/inboxes/bridge%40agentmail.test/messages/%3Cinbound%40example.test%3E/reply"
    )
    assert wrapped["body"] == {"text": "reply"}


def test_composio_transport_preserves_agentmail_authentication_labels() -> None:
    provider = ComposioAgentMailProvider(
        api_key="test-key",
        connected_account_id="ca_test",
        inbox_id="bridge@agentmail.test",
    )
    provider._opener = QueueOpener(  # type: ignore[assignment]
        [
            {
                "status": 200,
                "data": {"messages": [{"message_id": "in-1", "labels": ["received"]}]},
            },
            {
                "status": 200,
                "data": {
                    "message_id": "in-1",
                    "labels": ["received"],
                    "from": "person@example.test",
                    "to": ["bridge@agentmail.test"],
                    "timestamp": "2026-07-11T12:00:00Z",
                },
            },
        ]
    )
    messages = provider.poll(None).messages
    assert messages[0].sender_authentication is SenderAuthentication.AUTHENTICATED


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "https://attacker.test/v0/messages"),
        ("GET", "/inboxes/other/messages"),
        ("GET", "/inboxes/bridge%40agentmail.test/messages/../secrets"),
        ("GET", "/inboxes/bridge%40agentmail.test/messages/id%2Fsecrets"),
        ("POST", "/inboxes/bridge%40agentmail.test/messages/id"),
    ],
)
def test_proxy_rejects_arbitrary_hosts_paths_and_methods(method: str, path: str) -> None:
    provider, _opener = _provider({"status": 200, "data": {}})
    with pytest.raises(ComposioAgentMailError, match="unsupported"):
        provider._request(method, path)


@pytest.mark.parametrize(
    "payload",
    [
        ["not-an-object"],
        b"{invalid-json",
        {"data": {}},
        {"status": True, "data": {}},
        {"status": 200, "data": []},
    ],
)
def test_proxy_rejects_malformed_outer_and_upstream_responses(payload: Any) -> None:
    provider, _opener = _provider(payload)
    with pytest.raises(ComposioAgentMailError):
        provider._request("GET", "/inboxes/bridge%40agentmail.test/messages")


def test_proxy_errors_never_leak_keys_or_upstream_bodies() -> None:
    secret = "body-secret-never-log"
    provider, _opener = _provider({"status": 401, "data": {"detail": secret}})
    with pytest.raises(ComposioAgentMailError) as caught:
        provider._request("GET", "/inboxes/bridge%40agentmail.test/messages")
    rendered = str(caught.value)
    assert secret not in rendered
    assert "composio-test-key" not in rendered

    class ErrorOpener:
        def open(self, request: Request, timeout: float) -> Response:
            raise HTTPError(
                request.full_url,
                403,
                secret,
                Message(),
                io.BytesIO(secret.encode()),
            )

    provider._opener = ErrorOpener()  # type: ignore[assignment]
    with pytest.raises(ComposioAgentMailError) as outer:
        provider._request("GET", "/inboxes/bridge%40agentmail.test/messages")
    assert secret not in str(outer.value)
    assert "composio-test-key" not in str(outer.value)
    rendered_traceback = "".join(
        traceback.format_exception(type(outer.value), outer.value, outer.value.__traceback__)
    )
    assert secret not in rendered_traceback


def test_proxy_marks_only_transient_statuses_retryable_and_honors_safe_retry_after() -> None:
    provider, _opener = _provider(
        {"status": 429, "data": {"detail": "limited"}, "headers": {"Retry-After": "12"}}
    )
    with pytest.raises(RetryableProviderError) as caught:
        provider._request("GET", "/inboxes/bridge%40agentmail.test/messages")
    assert caught.value.retry_after == 12

    provider, _opener = _provider({"status": 503, "data": {}, "headers": {"Retry-After": "999999"}})
    with pytest.raises(RetryableProviderError) as unsafe:
        provider._request("GET", "/inboxes/bridge%40agentmail.test/messages")
    assert unsafe.value.retry_after is None


def test_composio_redirect_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    class RedirectHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/stolen")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            pass

    with HTTPServer(("127.0.0.1", 0), RedirectHandler) as server:
        thread = threading.Thread(target=server.handle_request)
        thread.start()
        monkeypatch.setattr(
            composio_module,
            "_PROXY_URL",
            f"http://127.0.0.1:{server.server_port}/api/v3.1/tools/execute/proxy",
        )
        provider = ComposioAgentMailProvider(
            api_key="secret", connected_account_id="ca_test", inbox_id="bridge@example.test"
        )
        with pytest.raises(ComposioAgentMailError, match="HTTP 302"):
            provider._request("GET", "/inboxes/bridge%40example.test/messages")
        thread.join(timeout=2)
        assert not thread.is_alive()
