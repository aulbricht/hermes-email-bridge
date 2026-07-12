"""Provider-neutral inbound email bridge for Hermes Agent."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("hermes-email-bridge")
except PackageNotFoundError:  # source tree without an installed distribution
    __version__ = "0.0.0+unknown"

from .models import Attachment, ConversationMapping, NormalizedEmail, SenderAuthentication

__all__ = ["Attachment", "ConversationMapping", "NormalizedEmail", "SenderAuthentication"]
