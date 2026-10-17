"""Optional import-owned route for authorized email conversations.

The bridge owns email delivery. An implementation may create or advance an import,
but must make ``operation_id`` idempotent before performing external work. It returns
only the text the bridge may send as one threaded reply; ``None`` means no reply.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from .models import Attachment, ConversationMapping, NormalizedEmail

AttachmentReader = Callable[[Attachment, int], bytes]


class ImportHandoff(Protocol):
    def wants(self, message: NormalizedEmail, mapping: ConversationMapping | None) -> bool:
        """Select a new import conversation from authorized message metadata."""

    def handle(
        self,
        message: NormalizedEmail,
        mapping: ConversationMapping | None,
        read_attachment: AttachmentReader,
        operation_id: str,
    ) -> str | None:
        """Advance one import step; never send email or invoke the generic runner."""
