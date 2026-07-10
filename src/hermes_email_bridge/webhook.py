"""Verified AgentMail-compatible webhook receiver using the standard library."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import threading
import time
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .providers.base import EmailProvider
from .service import BridgeService

logger = logging.getLogger(__name__)
MAX_PAYLOAD_BYTES = 1_048_576


class WebhookVerificationError(ValueError):
    """Webhook signature or timestamp is invalid."""


def verify_svix(
    payload: bytes,
    headers: Mapping[str, str],
    secret: str,
    *,
    now: float | None = None,
    tolerance: int = 300,
) -> None:
    """Verify AgentMail's Svix HMAC signature against the exact request body."""

    lower_headers = {key.lower(): value for key, value in headers.items()}
    message_id = lower_headers.get("svix-id", "")
    timestamp_value = lower_headers.get("svix-timestamp", "")
    signatures = lower_headers.get("svix-signature", "")
    if not message_id or not timestamp_value or not signatures:
        raise WebhookVerificationError("missing Svix verification headers")
    try:
        timestamp = int(timestamp_value)
    except ValueError as exc:
        raise WebhookVerificationError("invalid Svix timestamp") from exc
    if abs((time.time() if now is None else now) - timestamp) > tolerance:
        raise WebhookVerificationError("Svix timestamp is outside the tolerance window")

    encoded_secret = secret.removeprefix("whsec_")
    try:
        secret_bytes = base64.b64decode(encoded_secret, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise WebhookVerificationError("invalid webhook signing secret") from exc
    signed = f"{message_id}.{timestamp_value}.".encode() + payload
    expected = base64.b64encode(hmac.new(secret_bytes, signed, hashlib.sha256).digest()).decode()
    if not any(
        version == "v1" and hmac.compare_digest(signature, expected)
        for item in signatures.split()
        for version, separator, signature in [item.partition(",")]
        if separator
    ):
        raise WebhookVerificationError("invalid webhook signature")


def serve_webhooks(
    *,
    service: BridgeService,
    provider: EmailProvider,
    secret: str,
    host: str,
    port: int,
) -> None:
    """Serve `/webhooks` and `/healthz` until interrupted."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != "/healthz":
                self.send_error(404)
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok\n")

        def do_POST(self) -> None:
            if self.path != "/webhooks":
                self.send_error(404)
                return
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400, "invalid Content-Length")
                return
            if not 0 < content_length <= MAX_PAYLOAD_BYTES:
                self.send_error(413, "payload too large or empty")
                return
            raw = self.rfile.read(content_length)
            try:
                verify_svix(raw, dict(self.headers.items()), secret)
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    raise ValueError("payload must be a JSON object")
            except (WebhookVerificationError, json.JSONDecodeError, ValueError) as exc:
                logger.warning(
                    "webhook rejected",
                    extra={"event": "webhook_rejected", "reason": str(exc)},
                )
                self.send_error(400, "invalid webhook")
                return
            threading.Thread(
                target=_process_payload,
                args=(service, provider, payload),
                daemon=True,
            ).start()
            self.send_response(204)
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            logger.debug(
                "webhook request", extra={"event": "webhook_request", "detail": format % args}
            )

    server = ThreadingHTTPServer((host, port), Handler)
    logger.info(
        "webhook server started",
        extra={"event": "webhook_server_started", "host": host, "port": port},
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()


def _process_payload(
    service: BridgeService,
    provider: EmailProvider,
    payload: dict[str, Any],
) -> None:
    try:
        message = provider.parse_webhook(payload)
        if message is not None:
            service.handle(message)
    except Exception:
        logger.exception(
            "webhook message processing failed",
            extra={
                "event": "webhook_processing_error",
                "event_id": payload.get("event_id"),
            },
        )
