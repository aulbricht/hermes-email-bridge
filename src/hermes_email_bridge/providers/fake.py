"""In-memory provider for tests and integration experiments."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..models import NormalizedEmail, PollResult
from .base import EmailProvider


class FakeProvider(EmailProvider):
    name = "fake"

    def __init__(self, messages: Iterable[NormalizedEmail] = ()) -> None:
        self.messages = {message.provider_message_id: message for message in messages}
        self.replies: list[tuple[str, str]] = []

    def poll(self, cursor: str | None) -> PollResult:
        messages = tuple(self.messages.values())
        next_cursor = messages[-1].received_at.isoformat() if messages else cursor
        return PollResult(messages, next_cursor)

    def get(self, message_id: str) -> NormalizedEmail:
        return self.messages[message_id]

    def reply(self, message: NormalizedEmail, text: str) -> str:
        self.replies.append((message.provider_message_id, text))
        return f"fake-reply-{len(self.replies)}"

    def parse_webhook(self, payload: dict[str, Any]) -> NormalizedEmail | None:
        message_id = str(payload.get("message_id") or "")
        return self.messages.get(message_id)
