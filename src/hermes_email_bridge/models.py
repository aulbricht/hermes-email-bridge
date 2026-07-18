"""Provider-neutral bridge models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class SenderAuthentication(StrEnum):
    """Provider-asserted sender authentication state."""

    AUTHENTICATED = "authenticated"
    UNAUTHENTICATED = "unauthenticated"
    UNKNOWN = "unknown"


class ResolutionStatus(StrEnum):
    """Authorization-aware mapping resolution outcome."""

    AUTHORIZED = "authorized"
    DENIED = "denied"
    NO_MATCH = "no_match"


class HermesAction(StrEnum):
    """Only actions accepted from the no-tools Hermes adapter."""

    REPLY = "reply"
    APPROVAL_REQUIRED = "approval_required"


class ApprovalStatus(StrEnum):
    """Human-controlled states for quarantined email requests."""

    PENDING = "pending"
    RESOLVED = "resolved"
    REJECTED = "rejected"


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
    sender_authentication: SenderAuthentication = SenderAuthentication.UNKNOWN

    def as_dict(self, *, include_raw: bool = False) -> dict[str, Any]:
        value = asdict(self)
        value["received_at"] = self.received_at.isoformat()
        if not include_raw:
            value.pop("raw_payload", None)
        return value


@dataclass(frozen=True, slots=True)
class SentEmail:
    """Trusted outbound message metadata used to authorize future senders."""

    provider: str
    provider_message_id: str
    recipients: tuple[str, ...]
    sent_at: datetime


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
    bridge_marker_expires_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class MappingResolution:
    status: ResolutionStatus
    mapping: ConversationMapping | None = None
    matched_by: str | None = None


@dataclass(frozen=True, slots=True)
class PollResult:
    messages: tuple[NormalizedEmail, ...]
    cursor: str | None


@dataclass(frozen=True, slots=True)
class SentPollResult:
    messages: tuple[SentEmail, ...]
    cursor: str | None


@dataclass(frozen=True, slots=True)
class AllowlistEntry:
    provider: str
    address: str
    source: str
    source_message_id: str | None
    created_at: datetime
    updated_at: datetime
    revoked_at: datetime | None


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """Minimal metadata for a request that must not auto-dispatch."""

    id: int
    provider: str
    provider_message_id: str
    participant_email: str
    subject: str
    hermes_session: str
    status: ApprovalStatus
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class PollSummary:
    received: int
    processed: int
    skipped: int
    failed: int


@dataclass(frozen=True, slots=True)
class HermesResult:
    reply: str
    session_id: str
    action: HermesAction = HermesAction.REPLY


def utc_now() -> datetime:
    return datetime.now(UTC)
