"""Provider-neutral bridge models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class Attachment:
    """Attachment metadata; content is intentionally fetched on demand."""

    attachment_id: str | None = None
    filename: str | None = None
    content_type: str | None = None
    size: int | None = None
    inline: bool = False


@dataclass(frozen=True, slots=True)
class NormalizedEmail:
    """Common inbound message representation used by every provider."""

    provider: str
    provider_message_id: str
    from_email: str
    to_email: str
    subject: str
    text_body: str
    received_at: datetime
    from_name: str | None = None
    html_body: str | None = None
    in_reply_to: str | None = None
    references: tuple[str, ...] = ()
    thread_id: str | None = None
    attachments: tuple[Attachment, ...] = ()
    raw_payload: dict[str, Any] = field(default_factory=dict)

    def as_dict(self, *, include_raw: bool = False) -> dict[str, Any]:
        value = asdict(self)
        value["received_at"] = self.received_at.isoformat()
        if not include_raw:
            value.pop("raw_payload", None)
        return value


@dataclass(frozen=True, slots=True)
class ConversationMapping:
    """Persistent link between an email conversation and a Hermes route."""

    id: int
    provider: str
    hermes_session: str
    hermes_topic: str | None
    provider_thread_id: str | None
    subject_key: str | None
    participant_email: str | None
    bridge_marker: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ResolvedMapping:
    mapping: ConversationMapping
    matched_by: str


@dataclass(frozen=True, slots=True)
class PollResult:
    messages: tuple[NormalizedEmail, ...]
    cursor: str | None


@dataclass(frozen=True, slots=True)
class PollSummary:
    received: int
    processed: int
    skipped: int
    failed: int


@dataclass(frozen=True, slots=True)
class HermesResult:
    reply: str
    session_id: str | None


def utc_now() -> datetime:
    return datetime.now(UTC)
