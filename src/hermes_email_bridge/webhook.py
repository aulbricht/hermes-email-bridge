"""Verified AgentMail-compatible webhook receiver using the standard library."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import queue
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


class WebhookDispatcher:
    """Serialize Hermes work through one worker and a bounded queue."""

    def __init__(
        self,
        service: BridgeService,
        provider: EmailProvider,
        *,
        queue_size: int = 8,
    ) -> None:
        if queue_size <= 0:
            raise ValueError("queue_size must be positive")
        self.service = service
        self.provider = provider
        self._queue: queue.Queue[tuple[str | None, dict[str, Any]] | None] = queue.Queue(queue_size)
        self._lock = threading.Lock()
        self._pending: set[str] = set()
        self._stopped = False
        self._worker = threading.Thread(target=self._run, name="webhook-worker")
        self._worker.start()

    def submit(self, payload: dict[str, Any]) -> bool:
        key = _payload_key(payload)
        with self._lock:
            if self._stopped:
                return False
            if key and key in self._pending:
                return True
            if key:
                self._pending.add(key)
            try:
                self._queue.put_nowait((key, payload))
            except queue.Full:
                if key:
                    self._pending.remove(key)
                return False
        return True

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return
                key, payload = item
                _process_payload(self.service, self.provider, payload)
                if key:
                    with self._lock:
                        self._pending.remove(key)
            finally:
                self._queue.task_done()

    def shutdown(self) -> None:
        with self._lock:
            if self._stopped:
                return
            self._stopped = True
        self._queue.put(None)
        self._worker.join()


def _payload_key(payload: dict[str, Any]) -> str | None:
    message = payload.get("message")
    if isinstance(message, dict) and message.get("message_id"):
        return str(message["message_id"])
    for field in ("message_id", "event_id"):
        if payload.get(field):
            return str(payload[field])
    return None


def serve_webhooks(
    *,
    service: BridgeService,
    provider: EmailProvider,
    secret: str,
    host: str,
    port: int,
    queue_size: int = 8,
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
            if not dispatcher.submit(payload):
                self.send_error(503, "webhook queue full")
                return
            self.send_response(204)
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            logger.debug(
                "webhook request", extra={"event": "webhook_request", "detail": format % args}
            )

    dispatcher = WebhookDispatcher(service, provider, queue_size=queue_size)
    try:
        server = ThreadingHTTPServer((host, port), Handler)
    except Exception:
        dispatcher.shutdown()
        raise
    logger.info(
        "webhook server started",
        extra={"event": "webhook_server_started", "host": host, "port": port},
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
        dispatcher.shutdown()


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
