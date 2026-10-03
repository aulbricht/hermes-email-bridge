from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

_PATH = Path(__file__).resolve().parents[1] / "deploy/aws/nylas_receiver.py"
_SPEC = importlib.util.spec_from_file_location("nylas_receiver", _PATH)
assert _SPEC is not None and _SPEC.loader is not None
receiver = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(receiver)


def payload(trigger: str = "message.delivered") -> dict[str, Any]:
    obj: dict[str, Any] = {
        "message": {
            "id": "provider-message-1",
            "subject": "PRIVATE SUBJECT",
            "body": "PRIVATE BODY",
            "to": ["private@example.com"],
            "metadata": {
                "hermes_operation_id": "operation-1",
                "private_metadata": "PRIVATE SECRET",
            },
        }
    }
    if trigger == "message.delivered":
        obj["delivered"] = {"delivered_at": 1790980000, "recipients": ["private@example.com"]}
    elif trigger == "message.bounced":
        obj["bounce"] = {
            "bounced_at": 1790980000,
            "type": "MailboxFull",
            "recipients": [
                {"email": "private@example.com", "diagnostic_code": "PRIVATE DIAGNOSTIC"}
            ],
        }
    elif trigger == "message.complaint":
        obj["complaint"] = {
            "reported_at": 1790980000,
            "type": "abuse",
            "complained_recipients": ["private@example.com"],
        }
    elif trigger == "message.rejected":
        obj["rejected_at"] = 1790980000
    return {
        "specversion": "1.0",
        "type": trigger,
        "source": "/nylas/send",
        "id": "event-1",
        "time": 1790980001,
        "webhook_delivery_attempt": 1,
        "data": {"application_id": "application-1", "grant_id": "grant-1", "object": obj},
    }


def request(value: dict[str, Any], *, encoded: bool = False) -> dict[str, Any]:
    raw = json.dumps(value, indent=2).encode()
    signature = hmac.new(b"test-secret", raw, hashlib.sha256).hexdigest()
    return {
        "requestContext": {"http": {"method": "POST"}},
        "headers": {"X-Nylas-Signature": signature},
        "body": base64.b64encode(raw).decode() if encoded else raw.decode(),
        "isBase64Encoded": encoded,
    }


def receive(event: dict[str, Any], queue: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = receiver.receive(
        event,
        secret=lambda: "test-secret",
        enqueue=queue.append,
        application_id="application-1",
        grant_id="grant-1",
    )
    return result


@pytest.mark.parametrize(
    "trigger,status",
    [
        ("message.delivered", "delivered"),
        ("message.bounced", "bounced"),
        ("message.complaint", "complaint"),
        ("message.rejected", "rejected"),
    ],
)
@pytest.mark.parametrize("encoded", [True, False])
def test_official_agent_account_envelopes_are_authenticated_and_sanitized(
    trigger: str, status: str, encoded: bool
) -> None:
    queue: list[str] = []
    assert receive(request(payload(trigger), encoded=encoded), queue)["statusCode"] == 200
    event = json.loads(queue[0])
    assert event["status"] == status and event["operation_id"] == "operation-1"
    assert event["provider_message_id"] == "provider-message-1"
    assert "PRIVATE" not in queue[0] and "private@example.com" not in queue[0]
    assert event["occurred_at"] == "2026-10-02T22:26:40+00:00"


def test_get_challenge_is_exact_and_needs_no_secret() -> None:
    def unavailable() -> str:
        raise AssertionError("challenge must not access SSM")

    result = receiver.receive(
        {
            "requestContext": {"http": {"method": "GET"}},
            "queryStringParameters": {"challenge": 'exact+ /value"'},
        },
        secret=unavailable,
        enqueue=lambda _: None,
        application_id="application-1",
        grant_id="grant-1",
    )
    assert result["statusCode"] == 200 and result["body"] == 'exact+ /value"'


def test_signature_checks_raw_body_before_json() -> None:
    value = request(payload())
    value["body"] = json.dumps(payload(), separators=(",", ":"))
    queue: list[str] = []
    assert receive(value, queue)["statusCode"] == 401
    assert queue == []


@pytest.mark.parametrize("signature", ["", "z" * 64, "0" * 64, "sha256=" + "0" * 64])
def test_invalid_signatures(signature: str) -> None:
    value = request(payload())
    value["headers"] = {"x-nylas-signature": signature}
    queue: list[str] = []
    assert receive(value, queue)["statusCode"] == 401 and not queue


@pytest.mark.parametrize(
    "mutation", ["grant", "app", "source", "trigger", "timestamp", "message", "operation"]
)
def test_out_of_scope_or_invalid_payload_is_rejected(mutation: str) -> None:
    value = payload()
    if mutation == "grant":
        value["data"]["grant_id"] = "other-grant"
    elif mutation == "app":
        value["data"]["application_id"] = "other-application"
    elif mutation == "source":
        value["source"] = "/other/source"
    elif mutation == "trigger":
        value["type"] = "message.send_success"
    elif mutation == "timestamp":
        value["data"]["object"]["delivered"]["delivered_at"] = True
    elif mutation == "message":
        value["data"]["object"]["message"] = None
    else:
        value["data"]["object"]["message"]["metadata"]["hermes_operation_id"] = "invalid operation"
    queue: list[str] = []
    assert receive(request(value), queue)["statusCode"] == 400 and not queue


def test_absent_operation_metadata_keeps_message_correlation() -> None:
    value = payload()
    value["data"]["object"]["message"].pop("metadata")
    queue: list[str] = []
    assert receive(request(value), queue)["statusCode"] == 200
    assert json.loads(queue[0])["operation_id"] is None


def test_sqs_failure_returns_retryable_response() -> None:
    def unavailable(_: str) -> None:
        raise RuntimeError("sensitive queue exception")

    result = receiver.receive(
        request(payload()),
        secret=lambda: "test-secret",
        enqueue=unavailable,
        application_id="application-1",
        grant_id="grant-1",
    )
    assert result["statusCode"] == 503 and "sensitive" not in str(result)


def test_ssm_failure_returns_retryable_response() -> None:
    def unavailable() -> str:
        raise RuntimeError("sensitive SSM exception")

    result = receiver.receive(
        request(payload()),
        secret=unavailable,
        enqueue=lambda _: None,
        application_id="application-1",
        grant_id="grant-1",
    )
    assert result["statusCode"] == 503 and "sensitive" not in str(result)


def test_oversized_compressed_or_invalid_base64_rejected() -> None:
    value = request(payload())
    queue: list[str] = []
    value["body"] = "x" * 1_048_577
    assert receive(value, queue)["statusCode"] == 413
    value = request(payload())
    value["headers"]["content-encoding"] = "gzip"
    assert receive(value, queue)["statusCode"] == 415
    value = request(payload())
    value.update(isBase64Encoded=True, body="!!! invalid !!!")
    assert receive(value, queue)["statusCode"] == 400
    assert queue == []


def test_handler_fifo_deduplication_identity_ignores_webhook_delivery_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []
    enqueued: set[str] = set()

    class FakeSqs:
        def send_message(self, **kwargs: Any) -> None:
            calls.append(kwargs)
            # Model SQS FIFO's five-minute deduplication window. Durable SQLite
            # deduplication is independently tested after reopen/deletion failure.
            enqueued.add(kwargs["MessageDeduplicationId"])

    class FakeSsm:
        def get_parameter(self, **kwargs: Any) -> dict[str, Any]:
            assert kwargs == {"Name": "/email/webhook-secret", "WithDecryption": True}
            return {"Parameter": {"Value": "test-secret"}}

    clients = {"ssm": FakeSsm(), "sqs": FakeSqs()}
    def client(name: str) -> object:
        return clients[name]
    monkeypatch.setattr(
        receiver.importlib, "import_module", lambda _: SimpleNamespace(client=client)
    )
    monkeypatch.setenv("WEBHOOK_SECRET_PARAMETER", "/email/webhook-secret")
    monkeypatch.setenv("DELIVERY_QUEUE_URL", "https://sqs.example/queue.fifo")
    monkeypatch.setenv("NYLAS_APPLICATION_ID", "application-1")
    monkeypatch.setenv("NYLAS_GRANT_ID", "grant-1")
    value = payload()
    assert receiver.handler(request(value), None)["statusCode"] == 200
    value["webhook_delivery_attempt"] = 2
    assert receiver.handler(request(value), None)["statusCode"] == 200
    assert len(calls) == 2 and len(enqueued) == 1
    assert calls[0]["MessageDeduplicationId"] == calls[1]["MessageDeduplicationId"]
    assert calls[0]["MessageGroupId"] == hashlib.sha256(b"grant-1").hexdigest()
    assert "PRIVATE" not in json.dumps(calls)
