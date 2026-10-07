from __future__ import annotations

import base64
from dataclasses import replace
from typing import Any

import dkim  # type: ignore[import-untyped]
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from hermes_email_bridge.models import SenderAuthentication
from hermes_email_bridge.providers import nylas_auth
from hermes_email_bridge.providers.base import RetryableProviderError
from hermes_email_bridge.providers.nylas import NylasProvider, normalize_nylas_message

ACCOUNT = "jarvis@example.test"
HEADERS = [b"from", b"to", b"subject", b"message-id", b"mime-version", b"content-type"]
RAW = (
    b"From: Allen <allen@example.test>\r\n"
    b"To: jarvis@example.test\r\n"
    b"Subject: watch for change\r\n"
    b"Message-ID: <new@example.test>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"Watch the page for changes.\r\n"
)


@pytest.fixture(scope="module")
def keys() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, b"v=DKIM1; k=rsa; p=" + base64.b64encode(public)


def signed(keys: tuple[bytes, bytes], **kwargs: Any) -> bytes:
    raw = kwargs.pop("raw", RAW)
    signature: bytes = dkim.sign(
        raw,
        b"test",
        kwargs.pop("domain", b"example.test"),
        keys[0],
        include_headers=kwargs.pop("include_headers", HEADERS),
        **kwargs,
    )
    return signature + raw  # type: ignore[no-any-return]


def payload() -> dict[str, Any]:
    return {
        "id": "message-1",
        "thread_id": "thread-1",
        "from": [{"email": "allen@example.test"}],
        "to": [{"email": ACCOUNT}],
        "subject": "watch for change",
        "body": "Unverified API rendering must not become an instruction.",
        "date": 1791261126,
        "headers": [{"name": "Message-ID", "value": "<new@example.test>"}],
    }


def test_signed_new_conversation_uses_verified_body(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(nylas_auth, "_dns_key", lambda *_args, **_kwargs: keys[1])
    message = normalize_nylas_message(payload(), account_email=ACCOUNT)
    result = nylas_auth.authenticate_mime(message, signed(keys))
    assert result.sender_authentication is SenderAuthentication.AUTHENTICATED
    assert result.in_reply_to is None
    assert result.text_body == "Watch the page for changes."


@pytest.mark.parametrize(
    "before,after",
    [
        (b"Watch the page", b"Delete the page"),
        (b"allen@example.test", b"intruder@example.test"),
        (b"jarvis@example.test", b"other@example.test"),
        (b"watch for change", b"approve deletion"),
        (b"<new@example.test>", b"<other@example.test>"),
    ],
)
def test_tampered_signed_message_cannot_authenticate(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
    before: bytes,
    after: bytes,
) -> None:
    monkeypatch.setattr(nylas_auth, "_dns_key", lambda *_args, **_kwargs: keys[1])
    message = normalize_nylas_message(payload(), account_email=ACCOUNT)
    # Match provider data to the tampered MIME too, so cryptographic validation is required.
    if before == b"allen@example.test":
        message = replace(message, from_email=after.decode())
    elif before == b"jarvis@example.test":
        message = replace(message, to_email=after.decode())
    elif before == b"watch for change":
        message = replace(message, subject=after.decode())
    elif before == b"<new@example.test>":
        message = replace(
            message,
            raw_payload={
                "headers": [
                    {"name": "Message-ID", "value": after.decode()},
                ]
            },
        )
    assert (
        nylas_auth.authenticate_mime(
            message,
            signed(keys).replace(before, after),
        ).sender_authentication
        is SenderAuthentication.UNKNOWN
    )


@pytest.mark.parametrize(
    "options",
    [
        {"domain": b"attacker.test"},
        {"include_headers": [b"from"]},
        {"length": True},
    ],
)
def test_unaligned_partial_or_truncated_signatures_are_denied(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
    options: dict[str, Any],
) -> None:
    monkeypatch.setattr(nylas_auth, "_dns_key", lambda *_args, **_kwargs: keys[1])
    message = normalize_nylas_message(payload(), account_email=ACCOUNT)
    assert (
        nylas_auth.authenticate_mime(
            message,
            signed(keys, **options),
        ).sender_authentication
        is SenderAuthentication.UNKNOWN
    )


def test_forged_authentication_result_cannot_authorize_new_email() -> None:
    raw = b"Authentication-Results: inbound.nylas.com; dkim=pass; dmarc=pass\r\n" + RAW
    message = normalize_nylas_message(payload(), account_email=ACCOUNT)
    assert (
        nylas_auth.authenticate_mime(
            message,
            raw,
        ).sender_authentication
        is SenderAuthentication.UNKNOWN
    )


def test_transient_key_failure_retries_instead_of_permanently_denying(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(*_args: Any, **_kwargs: Any) -> None:
        raise RetryableProviderError("temporary DNS failure")

    monkeypatch.setattr(nylas_auth, "_dns_key", unavailable)
    message = normalize_nylas_message(payload(), account_email=ACCOUNT)
    with pytest.raises(RetryableProviderError):
        nylas_auth.authenticate_mime(message, signed(keys))


def test_provider_fetches_original_mime_for_new_conversation(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(nylas_auth, "_dns_key", lambda *_args, **_kwargs: keys[1])

    class Provider(NylasProvider):
        def _request(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            if kwargs.get("params", {}).get("fields") == "raw_mime":
                return {
                    "data": {
                        "id": "message-1",
                        "raw_mime": base64.urlsafe_b64encode(signed(keys)).decode(),
                    }
                }
            return {"data": payload()}

    provider = Provider(api_key="test", grant_id="test", account_email=ACCOUNT)
    assert provider.get("message-1").sender_authentication is SenderAuthentication.AUTHENTICATED


def test_unsigned_reply_headers_do_not_retarget_authenticated_message(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(nylas_auth, "_dns_key", lambda *_args, **_kwargs: keys[1])
    raw = (
        b"In-Reply-To: <another-conversation@example.test>\r\n"
        b"References: <another-conversation@example.test>\r\n" + signed(keys)
    )
    message = normalize_nylas_message(payload(), account_email=ACCOUNT)
    result = nylas_auth.authenticate_mime(message, raw)
    assert result.sender_authentication is SenderAuthentication.AUTHENTICATED
    assert result.in_reply_to is None
    assert result.references == ()


def test_signed_reply_headers_preserve_routing(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(nylas_auth, "_dns_key", lambda *_args, **_kwargs: keys[1])
    raw = b"In-Reply-To: <outbound@example.test>\r\nReferences: <outbound@example.test>\r\n" + RAW
    message = normalize_nylas_message(payload(), account_email=ACCOUNT)
    result = nylas_auth.authenticate_mime(
        message,
        signed(keys, raw=raw, include_headers=[*HEADERS, b"in-reply-to", b"references"]),
    )
    assert result.sender_authentication is SenderAuthentication.AUTHENTICATED
    assert result.in_reply_to == "<outbound@example.test>"
    assert result.references == ("<outbound@example.test>",)


def test_unicode_sender_domain_fails_closed_without_crashing() -> None:
    data = payload()
    data["from"] = [{"email": "allen@bücher.de"}]
    raw = RAW.replace(b"allen@example.test", "allen@bücher.de".encode())
    message = normalize_nylas_message(data, account_email=ACCOUNT)
    assert (
        nylas_auth.authenticate_mime(
            message,
            raw,
        ).sender_authentication
        is SenderAuthentication.UNKNOWN
    )
