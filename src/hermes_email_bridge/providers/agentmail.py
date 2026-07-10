"""AgentMail HTTP adapter.

Provider-specific API details live here so the bridge core remains reusable.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from email.utils import parseaddr
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..config import validate_agentmail_base_url
from ..models import Attachment, NormalizedEmail, PollResult, SenderAuthentication
from .base import EmailProvider


class AgentMailError(RuntimeError):
    """AgentMail API or payload error."""


def _first(value: Any) -> str:
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value or "")


def _parse_datetime(value: Any) -> datetime:
    if not value:
        return datetime.now(UTC)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def normalize_agentmail_message(
    payload: dict[str, Any],
    *,
    sender_authentication: SenderAuthentication = SenderAuthentication.UNKNOWN,
) -> NormalizedEmail:
    """Convert an AgentMail message or webhook object to the common model."""

    sender = _first(payload.get("from_") or payload.get("from"))
    from_name, from_email = parseaddr(sender)
    from_email = from_email or sender
    references_value = payload.get("references") or []
    references = (
        tuple(str(value) for value in references_value)
        if isinstance(references_value, list)
        else tuple(str(references_value).split())
    )
    attachments = tuple(
        Attachment(
            attachment_id=_string_or_none(item.get("attachment_id")),
            filename=_string_or_none(item.get("filename")),
            content_type=_string_or_none(item.get("content_type")),
            size=int(item["size"]) if item.get("size") is not None else None,
            inline=bool(item.get("inline")) or item.get("content_disposition") == "inline",
        )
        for item in payload.get("attachments") or []
        if isinstance(item, dict)
    )
    message_id = str(payload.get("message_id") or "")
    if not message_id:
        raise AgentMailError("AgentMail payload is missing message_id")
    return NormalizedEmail(
        provider="agentmail",
        provider_message_id=message_id,
        from_email=from_email.strip().lower(),
        from_name=from_name or None,
        to_email=_first(payload.get("to")).strip().lower(),
        subject=str(payload.get("subject") or ""),
        text_body=str(
            payload.get("extracted_text") or payload.get("text") or payload.get("preview") or ""
        ),
        html_body=_string_or_none(payload.get("extracted_html") or payload.get("html")),
        received_at=_parse_datetime(payload.get("timestamp") or payload.get("created_at")),
        in_reply_to=_string_or_none(payload.get("in_reply_to")),
        references=references,
        thread_id=_string_or_none(payload.get("thread_id")),
        attachments=attachments,
        raw_payload=dict(payload),
        sender_authentication=sender_authentication,
    )


def _string_or_none(value: Any) -> str | None:
    return str(value) if value is not None and value != "" else None


def _labels(payload: dict[str, Any]) -> set[str]:
    raw = payload.get("labels") or []
    values = raw if isinstance(raw, list) else [raw]
    return {str(value).strip().lower() for value in values}


def _classified_authentication(
    payload: dict[str, Any], fallback: SenderAuthentication
) -> SenderAuthentication:
    labels = _labels(payload)
    if "unauthenticated" in labels or fallback is SenderAuthentication.UNAUTHENTICATED:
        return SenderAuthentication.UNAUTHENTICATED
    if "received" in labels:
        return SenderAuthentication.AUTHENTICATED
    return fallback


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class AgentMailProvider(EmailProvider):
    """AgentMail REST adapter using only the Python standard library."""

    name = "agentmail"

    def __init__(
        self,
        *,
        api_key: str,
        inbox_id: str,
        base_url: str = "https://api.agentmail.to/v0",
        timeout: float = 30,
        allow_insecure_local_http: bool = False,
    ) -> None:
        self.api_key = api_key
        self.inbox_id = inbox_id
        self.base_url = validate_agentmail_base_url(
            base_url, allow_local_http=allow_insecure_local_http
        )
        self.timeout = timeout
        self._opener = build_opener(_NoRedirectHandler)

    @property
    def _inbox_path(self) -> str:
        return f"/inboxes/{quote(self.inbox_id, safe='')}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        if params:
            url = f"{url}?{urlencode(params, doseq=True)}"
        data = json.dumps(body).encode() if body is not None else None
        request = Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "hermes-email-bridge/0.2.0",
            },
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                decoded = json.loads(response.read())
        except HTTPError as exc:
            raise AgentMailError(f"AgentMail API returned HTTP {exc.code}") from exc
        except URLError as exc:
            raise AgentMailError(f"AgentMail API request failed: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise AgentMailError("AgentMail API returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise AgentMailError("AgentMail API returned an unexpected response")
        return decoded

    def poll(self, cursor: str | None) -> PollResult:
        params: dict[str, Any] = {
            "ascending": "true",
            "labels": ["received"],
            "limit": 100,
        }
        if cursor:
            # ponytail: one-second overlap avoids equal-timestamp gaps; the store deduplicates IDs.
            after = _parse_datetime(cursor) - timedelta(seconds=1)
            params["after"] = after.isoformat().replace("+00:00", "Z")

        messages: list[NormalizedEmail] = []
        seen: set[str] = set()
        latest = _parse_datetime(cursor) if cursor else None
        while True:
            response = self._request("GET", f"{self._inbox_path}/messages", params=params)
            summaries = response.get("messages") or []
            if not isinstance(summaries, list):
                raise AgentMailError("AgentMail messages response is malformed")
            for summary in summaries:
                if not isinstance(summary, dict):
                    continue
                message_id = str(summary.get("message_id") or "")
                labels = _labels(summary)
                if not message_id or message_id in seen:
                    continue
                if "received" not in labels or "unauthenticated" in labels:
                    continue
                seen.add(message_id)
                message = self._get(
                    message_id,
                    assumed_authentication=SenderAuthentication.AUTHENTICATED,
                )
                messages.append(message)
                if latest is None or message.received_at > latest:
                    latest = message.received_at
            page_token = response.get("next_page_token")
            if not page_token:
                break
            params["page_token"] = str(page_token)

        next_cursor = latest.isoformat().replace("+00:00", "Z") if latest else cursor
        return PollResult(tuple(messages), next_cursor)

    def get(self, message_id: str) -> NormalizedEmail:
        return self._get(message_id)

    def _get(
        self,
        message_id: str,
        *,
        assumed_authentication: SenderAuthentication = SenderAuthentication.UNKNOWN,
    ) -> NormalizedEmail:
        payload = self._request(
            "GET",
            f"{self._inbox_path}/messages/{quote(message_id, safe='')}",
        )
        return normalize_agentmail_message(
            payload,
            sender_authentication=_classified_authentication(payload, assumed_authentication),
        )

    def reply(self, message: NormalizedEmail, text: str) -> str:
        response = self._request(
            "POST",
            f"{self._inbox_path}/messages/{quote(message.provider_message_id, safe='')}/reply",
            body={"text": text},
        )
        message_id = str(response.get("message_id") or "")
        if not message_id:
            raise AgentMailError("AgentMail reply response is missing message_id")
        return message_id

    def parse_webhook(self, payload: dict[str, Any]) -> NormalizedEmail | None:
        event_type = str(payload.get("event_type") or "")
        event_authentication = {
            "message.received": SenderAuthentication.AUTHENTICATED,
            "message.unauthenticated": SenderAuthentication.UNAUTHENTICATED,
            "message.received.unauthenticated": SenderAuthentication.UNAUTHENTICATED,
        }.get(event_type)
        if event_authentication is None:
            return None
        message = payload.get("message")
        if not isinstance(message, dict):
            raise AgentMailError(f"{event_type} webhook is missing message data")
        payload_inbox = str(message.get("inbox_id") or "")
        raw_recipients = message.get("to") or []
        if not isinstance(raw_recipients, list):
            raw_recipients = [raw_recipients]
        recipients = [str(item).lower() for item in raw_recipients]
        if payload_inbox != self.inbox_id and self.inbox_id.lower() not in recipients:
            raise AgentMailError("webhook message does not belong to the configured inbox")
        authentication = _classified_authentication(message, event_authentication)
        if not message.get("text") and not message.get("html"):
            return self._get(
                str(message.get("message_id") or ""),
                assumed_authentication=authentication,
            )
        return normalize_agentmail_message(message, sender_authentication=authentication)
