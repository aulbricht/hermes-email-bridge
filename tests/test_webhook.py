import base64
import hashlib
import hmac

import pytest

from hermes_email_bridge.webhook import WebhookVerificationError, verify_svix


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
