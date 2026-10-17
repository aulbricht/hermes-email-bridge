"""Optional HTTPS-only transport to the dedicated Atlas import ingress."""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from .import_handoff import AttachmentReader
from .models import ConversationMapping, NormalizedEmail, SenderAuthentication

_PATH = "/api/v1/internal/email-import-handoff"
_MAX_BYTES = 25 * 1024 * 1024
_MIME = {
    ".pdf": "application/pdf",
    ".csv": "text/csv",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, request: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str,
    ) -> None:
        return None


def _token(path: Path) -> str:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o077):
        raise RuntimeError("Atlas import token file is unsafe")
    value = path.read_text(encoding="utf-8").strip()
    if len(value) < 32 or len(value) > 512:
        raise RuntimeError("Atlas import token file is invalid")
    return value


class AtlasImportHandoff:
    def __init__(self, *, origin: str, token_file: Path, grant_id: str) -> None:
        if not origin.startswith("https://") or not grant_id:
            raise ValueError("Atlas import transport is not configured")
        self.origin = origin.rstrip("/")
        self.token_file = token_file
        self.grant_id = grant_id

    def wants(self, message: NormalizedEmail, mapping: ConversationMapping | None) -> bool:
        if (message.provider != "nylas" or mapping is not None or
            message.sender_authentication is not SenderAuthentication.AUTHENTICATED or
            len(message.attachments) != 1):
            return False
        attachment = message.attachments[0]
        if (attachment.inline or not attachment.attachment_id or not attachment.filename or
            (attachment.size is not None and attachment.size > _MAX_BYTES)):
            return False
        suffix = Path(attachment.filename).suffix.lower()
        declared = (attachment.content_type or "").split(";", 1)[0].strip().lower()
        return suffix in _MIME and declared in ({_MIME[suffix], "application/octet-stream"} | (
            {"text/plain"} if suffix == ".csv" else set()
        ))

    def handle(
        self, message: NormalizedEmail, mapping: ConversationMapping | None,
        read_attachment: AttachmentReader, operation_id: str,
    ) -> str | None:
        if message.provider != "nylas" or not message.thread_id:
            raise ValueError("Atlas import requires a Nylas thread")
        envelope: dict[str, object] = {
            "action": "reply" if not message.attachments else "import",
            "grant_id": self.grant_id, "message_id": message.provider_message_id,
            "thread_id": message.thread_id, "sender_email": message.from_email,
            "authentication": str(message.sender_authentication),
            "attachment_ids": [item.attachment_id for item in message.attachments],
            "operation_id": operation_id,
        }
        if message.attachments:
            if not self.wants(message, mapping):
                raise ValueError("Atlas import attachment is unsupported or ambiguous")
            attachment = message.attachments[0]
            assert attachment.filename is not None and attachment.attachment_id is not None
            suffix = Path(attachment.filename).suffix.lower()
            declared = (attachment.content_type or "").split(";", 1)[0].strip().lower()
            if declared not in {_MIME[suffix], "application/octet-stream"} | (
                {"text/plain"} if suffix == ".csv" else set()
            ):
                raise ValueError("Atlas import attachment MIME is unsupported")
            content = read_attachment(attachment, _MAX_BYTES)
            envelope.update({
                "attachment_id": attachment.attachment_id,
                "filename": attachment.filename,
                "declared_content_type": declared,
                "content_b64": base64.b64encode(content).decode("ascii"),
            })
        elif message.sender_authentication not in {
            SenderAuthentication.AUTHENTICATED, SenderAuthentication.REPLY_PROVEN,
        }:
            raise ValueError("Atlas import reply is unauthenticated")
        body = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        request = Request(
            self.origin + _PATH, data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "X-Atlas-Email-Import-Token": _token(self.token_file)},
        )
        opener = build_opener(ProxyHandler({}), HTTPSHandler(), _NoRedirect())
        try:
            with opener.open(request, timeout=30) as response:
                if response.status != 200:
                    raise RuntimeError("Atlas import response is uncertain")
                result = json.loads(response.read(16_385))
        except (HTTPError, URLError, TimeoutError, ValueError) as exc:
            raise RuntimeError(
                "Atlas import response is uncertain; reconcile before retry"
            ) from exc
        if (not isinstance(result, dict) or result.get("status") != "accepted" or
            any(not isinstance(result.get(key), str) or not result[key]
                for key in ("owner_user_id", "session_id", "upload_id", "import_id"))):
            raise RuntimeError("Atlas import response is uncertain; reconcile before retry")
        # Email is owned solely by the bridge; a customer-facing approval URL is not yet verified.
        return None
