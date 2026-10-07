"""Verify new Nylas conversations against the original DKIM-signed MIME bytes."""

from __future__ import annotations

from dataclasses import replace
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses

import dkim  # type: ignore[import-untyped]
import dns.exception
import dns.resolver

from ..mapping import normalize_email_address
from ..models import NormalizedEmail, SenderAuthentication
from .base import RetryableProviderError

_SIGNED_HEADERS = {b"from", b"to", b"subject", b"message-id", b"mime-version", b"content-type"}


def _dns_key(name: bytes, timeout: float = 5) -> bytes | None:
    try:
        answers = dns.resolver.resolve(name.decode("ascii"), "TXT", lifetime=min(timeout, 5))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except dns.exception.DNSException:
        raise RetryableProviderError("DKIM key lookup is temporarily unavailable") from None
    values = [b"".join(answer.strings) for answer in answers]
    return values[0] if len(values) == 1 else None


def authenticate_mime(message: NormalizedEmail, raw: bytes) -> NormalizedEmail:
    """Authenticate aligned signatures and use the verified MIME body, never API rendering.

    Unsigned messages retain the existing reply-possession path. No authentication-result
    header, even one naming Nylas, can authorize a new conversation.
    """
    mime = BytesParser(policy=policy.default).parsebytes(raw)
    for name in ("From", "To", "Subject", "Message-ID", "MIME-Version", "Content-Type"):
        if len(mime.get_all(name, [])) != 1:
            return message
    if mime.get_all("Cc") or mime.get_all("Bcc") or mime.defects:
        return message
    try:
        senders = getaddresses([str(mime["From"])])
        recipients = getaddresses([str(mime["To"])])
        if (
            len(senders) != 1
            or len(recipients) != 1
            or normalize_email_address(senders[0][1]) != message.from_email
            or normalize_email_address(recipients[0][1]) != message.to_email
            or str(mime["Subject"]) != message.subject
        ):
            return message
    except ValueError:
        return message
    api_ids = [
        h.get("value")
        for h in message.raw_payload.get("headers", [])
        if isinstance(h, dict) and str(h.get("name", "")).lower() == "message-id"
    ]
    if api_ids != [str(mime["Message-ID"])]:
        return message
    try:
        domain = message.from_email.rsplit("@", 1)[1].encode("idna").lower()
    except UnicodeError:
        return message
    verifier = dkim.DKIM(raw)
    authenticated = False
    verified_headers: set[bytes] = set()
    for index, signature in enumerate(mime.get_all("DKIM-Signature", [])):
        try:
            tags = dkim.util.parse_tag_value(str(signature).encode("ascii"))
            signed = {h.strip().lower() for h in tags.get(b"h", b"").split(b":")}
            if (
                tags.get(b"d", b"").lower() != domain
                or b"l" in tags
                or tags.get(b"a") != b"rsa-sha256"
                or not signed >= _SIGNED_HEADERS
            ):
                continue
            if verifier.verify(idx=index, dnsfunc=_dns_key):
                authenticated = True
                verified_headers = signed
                break
        except (dkim.DKIMException, ValueError, UnicodeError):
            continue
    if not authenticated:
        return message
    # Forwarded messages and attachments are not agent instructions. get_body selects
    # only the top-level MIME body's preferred text part.
    body = mime.get_body(preferencelist=("plain", "html"))
    if body is None:
        return message
    try:
        content = body.get_content()
    except (LookupError, ValueError):
        return message
    if not isinstance(content, str):
        return message
    from .nylas import _body_to_text

    is_html = body.get_content_type() == "text/html"
    return replace(
        message,
        text_body=_body_to_text(content) if is_html else content[:100_000].strip(),
        html_body=content[:100_000] if is_html else None,
        in_reply_to=(
            str(mime["In-Reply-To"])
            if b"in-reply-to" in verified_headers and len(mime.get_all("In-Reply-To", [])) == 1
            else None
        ),
        references=(
            tuple(str(mime["References"]).split())
            if b"references" in verified_headers and len(mime.get_all("References", [])) == 1
            else ()
        ),
        sender_authentication=SenderAuthentication.AUTHENTICATED,
    )
