"""Provider-neutral inbound email bridge for Hermes Agent."""

from .models import Attachment, ConversationMapping, NormalizedEmail, SenderAuthentication

__all__ = ["Attachment", "ConversationMapping", "NormalizedEmail", "SenderAuthentication"]
__version__ = "0.2.0"
