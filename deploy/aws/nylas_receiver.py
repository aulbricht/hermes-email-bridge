"""AWS Lambda HTTP API v2 receiver. Deploy this file as nylas_receiver.py.

Schemas: https://developer.nylas.com/docs/reference/notifications/agent-accounts/
Each trigger's /index.md documents data.object.message and the outcome timestamp.
Only these Agent Account events are allowed; scheduled-send success is excluded.
Configure uncompressed webhooks. SSM contains the endpoint webhook_secret, never
the Nylas API key. No raw payload, addresses, content or signature is persisted.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
import os
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

_TRIGGERS = {
    "message.delivered": ("delivered", "delivered", "delivered_at"),
    "message.bounced": ("bounced", "bounce", "bounced_at"),
    "message.complaint": ("complaint", "complaint", "reported_at"),
    "message.rejected": ("rejected", None, "rejected_at"),
}
_OPERATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MAX_BODY = 1_048_576


def _id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 998
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError("invalid identifier")
    return value


def normalize(payload: object, *, application_id: str, grant_id: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("specversion") != "1.0":
        raise ValueError("invalid notification")
    trigger = payload.get("type")
    if not isinstance(trigger, str) or trigger not in _TRIGGERS:
        raise ValueError("unsupported notification")
    if payload.get("source") != "/nylas/send":
        raise ValueError("unexpected notification source")
    data = payload.get("data")
    if not isinstance(data, dict) or data.get("application_id") != application_id:
        raise ValueError("application scope mismatch")
    if data.get("grant_id") != grant_id:
        raise ValueError("grant scope mismatch")
    obj = data.get("object")
    if not isinstance(obj, dict) or not isinstance(obj.get("message"), dict):
        raise ValueError("invalid message envelope")
    message = obj["message"]
    status, detail, timestamp_name = _TRIGGERS[trigger]
    outcome = obj.get(detail) if detail else obj
    if not isinstance(outcome, dict):
        raise ValueError("invalid outcome")
    timestamp = outcome.get(timestamp_name)
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp < 0:
        raise ValueError("invalid outcome timestamp")
    occurred_at = datetime.fromtimestamp(timestamp, UTC).isoformat()
    metadata = message.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("invalid metadata")
    operation_id = metadata.get("hermes_operation_id")
    if operation_id is not None and (
        not isinstance(operation_id, str) or not _OPERATION.fullmatch(operation_id)
    ):
        raise ValueError("invalid operation metadata")
    return {
        "version": 1,
        "event_id": _id(payload.get("id")),
        "provider": "nylas",
        "grant_id": grant_id,
        "status": status,
        "occurred_at": occurred_at,
        "operation_id": operation_id,
        "provider_message_id": _id(message.get("id")),
        "rfc_message_id": None,
    }


def response(status: int, body: str = "") -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "text/plain"},
        "body": body,
        "isBase64Encoded": False,
    }


def receive(
    event: dict[str, Any],
    *,
    secret: Callable[[], str],
    enqueue: Callable[[str], None],
    application_id: str,
    grant_id: str,
) -> dict[str, Any]:
    method = event.get("requestContext", {}).get("http", {}).get("method")
    if method == "GET":
        challenge = (event.get("queryStringParameters") or {}).get("challenge")
        if not isinstance(challenge, str) or not challenge or len(challenge) > 4096:
            return response(400)
        return response(200, challenge)
    if method != "POST":
        return response(405)
    headers = {str(key).lower(): value for key, value in (event.get("headers") or {}).items()}
    if headers.get("content-encoding", "identity") != "identity":
        return response(415)  # register with compressed_delivery=false
    body = event.get("body")
    if not isinstance(body, str) or len(body) > 2 * _MAX_BODY:
        return response(413)
    try:
        raw = (
            base64.b64decode(body, validate=True) if event.get("isBase64Encoded") else body.encode()
        )
    except (ValueError, UnicodeError):
        return response(400)
    if len(raw) > _MAX_BODY:
        return response(413)
    signature = headers.get("x-nylas-signature", "")
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", signature):
        return response(401)
    try:
        webhook_secret = secret()
        if not webhook_secret:
            return response(503)
    except Exception:
        return response(503)
    try:
        expected = hmac.new(webhook_secret.encode(), raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature.lower()):
            return response(401)
        normalized = normalize(json.loads(raw), application_id=application_id, grant_id=grant_id)
    except (ValueError, TypeError, OverflowError, OSError):
        return response(400)
    except Exception:
        return response(503)
    try:
        enqueue(json.dumps(normalized, sort_keys=True, separators=(",", ":")))
    except Exception:
        return response(503)
    return response(200)


def handler(event: dict[str, Any], context: object) -> dict[str, Any]:
    del context

    # Read current SSM secret on every request so rotations do not leave warm
    # Lambdas authenticating with a stale key. GET verification needs no secret.
    def secret() -> str:
        boto3 = importlib.import_module("boto3")
        parameter = boto3.client("ssm").get_parameter(
            Name=os.environ["WEBHOOK_SECRET_PARAMETER"], WithDecryption=True
        )
        value = parameter["Parameter"]["Value"]
        if not isinstance(value, str):
            raise ValueError("invalid webhook secret")
        return value

    def enqueue(body: str) -> None:
        boto3 = importlib.import_module("boto3")
        normalized = json.loads(body)
        identity = json.dumps(
            [normalized["provider"], normalized["event_id"]], separators=(",", ":")
        ).encode()
        boto3.client("sqs").send_message(
            QueueUrl=os.environ["DELIVERY_QUEUE_URL"],
            MessageBody=body,
            MessageGroupId=hashlib.sha256(normalized["grant_id"].encode()).hexdigest(),
            MessageDeduplicationId=hashlib.sha256(identity).hexdigest(),
        )

    return receive(
        event,
        secret=secret,
        enqueue=enqueue,
        application_id=os.environ["NYLAS_APPLICATION_ID"],
        grant_id=os.environ["NYLAS_GRANT_ID"],
    )
