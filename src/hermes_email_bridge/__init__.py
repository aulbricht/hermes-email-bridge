"""Provider-neutral inbound email bridge for Hermes Agent."""

from .models import Attachment, ConversationMapping, NormalizedEmail

__all__ = ["Attachment", "ConversationMapping", "NormalizedEmail"]
__version__ = "0.1.0"
