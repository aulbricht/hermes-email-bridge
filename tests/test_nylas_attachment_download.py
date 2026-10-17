from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from hermes_email_bridge.models import Attachment, SenderAuthentication
from hermes_email_bridge.providers.nylas import NylasError, NylasProvider, normalize_nylas_message


class Response:
    def __init__(self, payload: bytes, length: str | None = None) -> None:
        self.payload = payload
        self.headers = {"Content-Length": length} if length is not None else {}

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *_args: object) -> None:
        pass

    def read(self, count: int) -> bytes:
        return self.payload[:count]


class Opener:
    def __init__(self, response: Response) -> None:
        self.response = response
        self.requests: list[Any] = []

    def open(self, request: Any, *, timeout: float) -> Response:
        self.requests.append((request, timeout))
        return self.response


def test_download_uses_encoded_id_and_message_binding() -> None:
    provider = NylasProvider(api_key="test", grant_id="grant-1", account_email="agent@example.test")
    message = normalize_nylas_message(
        {
            "id": "message/#1",
            "thread_id": "thread-1",
            "from": [{"email": "owner@example.test"}],
            "to": [{"email": "agent@example.test"}],
            "date": 1_700_000_000,
            "attachments": [{"id": "attachment/#1", "filename": "rent.pdf", "size": 4}],
        },
        account_email="agent@example.test",
    )
    message = replace(message, sender_authentication=SenderAuthentication.AUTHENTICATED)
    opener = Opener(Response(b"%PDF", "4"))
    provider._opener = opener  # type: ignore[assignment]

    assert provider.download_attachment(message, message.attachments[0], max_bytes=10) == b"%PDF"
    request, timeout = opener.requests[0]
    assert "/attachments/attachment%2F%231/download?message_id=message%2F%231" in request.full_url
    assert timeout == provider.timeout
    assert request.get_header("Authorization") == "Bearer test"


def test_download_rejects_unlisted_inline_and_oversize() -> None:
    provider = NylasProvider(api_key="test", grant_id="grant-1", account_email="agent@example.test")
    message = normalize_nylas_message(
        {
            "id": "message-1",
            "thread_id": "thread-1",
            "from": [{"email": "owner@example.test"}],
            "to": [{"email": "agent@example.test"}],
            "date": 1_700_000_000,
            "attachments": [{"id": "attachment-1", "filename": "rent.pdf", "size": 4}],
        },
        account_email="agent@example.test",
    )
    message = replace(message, sender_authentication=SenderAuthentication.AUTHENTICATED)
    with pytest.raises(NylasError):
        provider.download_attachment(
            replace(message, sender_authentication=SenderAuthentication.UNKNOWN),
            message.attachments[0], max_bytes=10,
        )
    with pytest.raises(NylasError):
        provider.download_attachment(message, Attachment("different"), max_bytes=10)
    with pytest.raises(NylasError):
        provider.download_attachment(
            message, replace(message.attachments[0], inline=True), max_bytes=10
        )
    with pytest.raises(NylasError):
        provider.download_attachment(message, message.attachments[0], max_bytes=3)
    provider._opener = Opener(Response(b"123456"))  # type: ignore[assignment]
    with pytest.raises(NylasError):
        provider.download_attachment(message, message.attachments[0], max_bytes=5)
