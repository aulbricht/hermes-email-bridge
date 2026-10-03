"""Provider adapter contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..models import NormalizedEmail, PollResult, SentPollResult


class RetryableProviderError(RuntimeError):
    """A transient provider failure that continuous polling may retry."""

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class AmbiguousSendError(RuntimeError):
    """The provider might have accepted a send whose result was not observed."""


class EmailProvider(ABC):
    """Minimum contract for inbound polling, inspection, webhooks, and replies.

    Adapters must set ``sender_authentication`` only from provider-trusted API
    evidence or a verified webhook event, never from raw email headers alone.
    """

    name: str
    requires_reply_proof = False

    @abstractmethod
    def poll(self, cursor: str | None) -> PollResult:
        """Return inbound messages after a provider-specific cursor."""

    @abstractmethod
    def poll_sent(self, cursor: str | None) -> SentPollResult:
        """Return trusted outbound metadata after a separate provider cursor."""

    @abstractmethod
    def get(self, message_id: str) -> NormalizedEmail:
        """Fetch and normalize one provider message."""

    @abstractmethod
    def reply(self, message: NormalizedEmail, text: str) -> str:
        """Reply in the provider's existing email thread and return its message ID."""

    def send(
        self,
        *,
        operation_id: str,
        to: str,
        subject: str,
        text: str | None,
        html: str | None,
    ) -> str:
        """Send one initiated message without accepting a caller-selected identity."""

        raise NotImplementedError(f"{self.name} does not support initiated sends")

    def parse_webhook(self, payload: dict[str, Any]) -> NormalizedEmail | None:
        """Normalize a verified webhook payload, or ignore unsupported event types."""

        raise NotImplementedError(f"{self.name} does not support webhooks")

    def delivery_identity(
        self, operation_id: str, message_id: str
    ) -> tuple[str, str | None, str | None] | None:
        """Optional grant, provider ID and RFC Message-ID for accepted sends."""
        return None
