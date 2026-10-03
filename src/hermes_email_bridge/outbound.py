"""Provider-neutral initiated-send journal and duplicate suppression."""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass
from hashlib import sha256

from .mapping import normalize_email_address
from .models import OutboundState
from .providers.base import AmbiguousSendError, EmailProvider
from .store import MappingStore

_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MAX_BODY_CHARACTERS = 1_000_000


@dataclass(frozen=True, slots=True)
class OutboundResult:
    provider_message_id: str
    duplicate: bool


class OutboundService:
    def __init__(self, *, provider: EmailProvider, store: MappingStore) -> None:
        self.provider = provider
        self.store = store
        self._lock = threading.Lock()

    def send(
        self,
        *,
        operation_id: str,
        to: str,
        subject: str,
        text: str | None = None,
        html: str | None = None,
    ) -> OutboundResult:
        """Send once or return the prior terminal result for the operation ID."""

        with self._lock:
            return self._send_serialized(
                operation_id=operation_id,
                to=to,
                subject=subject,
                text=text,
                html=html,
            )

    def _send_serialized(
        self,
        *,
        operation_id: str,
        to: str,
        subject: str,
        text: str | None,
        html: str | None,
    ) -> OutboundResult:
        if not _OPERATION_ID.fullmatch(operation_id):
            raise ValueError("operation_id must be an opaque 1-128 character identifier")
        recipient = normalize_email_address(to)
        if not subject or "\r" in subject or "\n" in subject or len(subject) > 998:
            raise ValueError("subject must be nonempty, single-line, and at most 998 characters")
        if not text and not html:
            raise ValueError("text or html is required")
        if text is not None and len(text) > _MAX_BODY_CHARACTERS:
            raise ValueError("text body exceeds the safety limit")
        if html is not None and len(html) > _MAX_BODY_CHARACTERS:
            raise ValueError("HTML body exceeds the safety limit")

        canonical = json.dumps(
            {
                "html": html,
                "subject": subject,
                "text": text,
                "to": recipient,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        payload_hash = sha256(canonical).hexdigest()
        operation, claimed = self.store.claim_outbound_operation(
            self.provider.name,
            operation_id,
            payload_hash,
        )
        if not claimed:
            if operation.state is OutboundState.SENT and operation.provider_message_id:
                return OutboundResult(operation.provider_message_id, duplicate=True)
            if operation.state in {OutboundState.PENDING, OutboundState.UNCERTAIN}:
                raise AmbiguousSendError(
                    "operation has no terminal delivery result; automatic retry suppressed"
                )
            raise RuntimeError("operation previously failed; automatic retry suppressed")

        try:
            message_id = self.provider.send(
                operation_id=operation_id,
                to=recipient,
                subject=subject,
                text=text,
                html=html,
            )
        except AmbiguousSendError:
            self.store.set_outbound_state(
                self.provider.name,
                operation_id,
                OutboundState.UNCERTAIN,
            )
            raise
        except Exception:
            self.store.set_outbound_state(
                self.provider.name,
                operation_id,
                OutboundState.FAILED,
            )
            raise
        self.store.set_outbound_state(
            self.provider.name,
            operation_id,
            OutboundState.SENT,
            provider_message_id=message_id,
        )
        return OutboundResult(message_id, duplicate=False)
