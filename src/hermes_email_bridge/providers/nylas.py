"""Nylas Agent Account transport using the provider-neutral bridge contract."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from html.parser import HTMLParser
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .. import __version__
from ..config import validate_api_base_url
from ..mapping import normalize_email_address
from ..models import (
    Attachment,
    NormalizedEmail,
    PollResult,
    SenderAuthentication,
    SentEmail,
    SentPollResult,
)
from .base import AmbiguousSendError, EmailProvider, RetryableProviderError

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_BODY_CHARACTERS = 100_000
_MAX_ATTACHMENTS = 64
_MAX_PAGES = 25
_BLOCK_TAGS = {
    "address",
    "blockquote",
    "br",
    "div",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "li",
    "ol",
    "p",
    "pre",
    "table",
    "td",
    "th",
    "tr",
    "ul",
}


class NylasError(RuntimeError):
    """A non-retryable Nylas API, configuration, or payload failure."""


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


class _BoundedHTMLTextExtractor(HTMLParser):
    def __init__(self, limit: int = _MAX_BODY_CHARACTERS) -> None:
        super().__init__(convert_charrefs=True)
        self.limit = limit
        self.parts: list[str] = []
        self.length = 0
        self.hidden_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        lowered = tag.lower()
        if lowered in {"script", "style"}:
            self.hidden_depth += 1
        elif lowered in _BLOCK_TAGS:
            self._append("\n")

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered in {"script", "style"} and self.hidden_depth:
            self.hidden_depth -= 1
        elif lowered in _BLOCK_TAGS:
            self._append("\n")

    def handle_data(self, data: str) -> None:
        if not self.hidden_depth:
            self._append(data)

    def _append(self, value: str) -> None:
        if self.length >= self.limit:
            return
        clipped = value[: self.limit - self.length]
        self.parts.append(clipped)
        self.length += len(clipped)

    def text(self) -> str:
        value = "".join(self.parts)
        value = re.sub(r"[ \t\f\v]+", " ", value)
        value = re.sub(r" *\n *", "\n", value)
        value = re.sub(r"\n{3,}", "\n\n", value)
        return value.strip()


def _body_to_text(value: Any) -> str:
    body = str(value or "")[:_MAX_BODY_CHARACTERS]
    parser = _BoundedHTMLTextExtractor()
    parser.feed(body)
    parser.close()
    return parser.text()


def _epoch(value: Any) -> datetime:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise NylasError("Nylas message is missing a valid date")
    try:
        return datetime.fromtimestamp(value, tz=UTC)
    except (OSError, OverflowError, ValueError) as exc:
        raise NylasError("Nylas message has an invalid date") from exc


def _addresses(value: Any) -> tuple[tuple[str | None, str], ...]:
    if not isinstance(value, list):
        return ()
    parsed: list[tuple[str | None, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        raw_email = item.get("email")
        if not isinstance(raw_email, str):
            continue
        try:
            email = normalize_email_address(raw_email)
        except ValueError:
            continue
        raw_name = item.get("name")
        name = str(raw_name) if raw_name not in {None, ""} else None
        parsed.append((name, email))
    return tuple(parsed)


def _headers(payload: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    raw_headers = payload.get("headers")
    if not isinstance(raw_headers, list):
        return result
    for item in raw_headers:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        value = item.get("value")
        if isinstance(name, str) and isinstance(value, str):
            result.setdefault(name.strip().lower(), []).append(value.strip())
    return result


def _first_header(payload: dict[str, Any], name: str) -> str | None:
    values = _headers(payload).get(name.lower(), [])
    return values[0] if values and values[0] else None


def _references(payload: dict[str, Any]) -> tuple[str, ...]:
    value = _first_header(payload, "references")
    return tuple(value.split()) if value else ()


def normalize_nylas_message(
    payload: dict[str, Any],
    *,
    account_email: str,
) -> NormalizedEmail:
    """Convert one Nylas message after enforcing the isolated recipient."""

    message_id = payload.get("id")
    thread_id = payload.get("thread_id")
    if not isinstance(message_id, str) or not message_id:
        raise NylasError("Nylas message is missing an id")
    if not isinstance(thread_id, str) or not thread_id:
        raise NylasError("Nylas message is missing a thread id")

    senders = _addresses(payload.get("from"))
    recipients = _addresses(payload.get("to"))
    if len(senders) != 1:
        raise NylasError("Nylas message must have exactly one sender")
    if len(recipients) != 1 or recipients[0][1] != account_email:
        raise NylasError("Nylas message is not addressed only to the configured account")
    if _addresses(payload.get("cc")) or _addresses(payload.get("bcc")):
        raise NylasError("Nylas message has additional recipients")

    attachments: list[Attachment] = []
    raw_attachments = payload.get("attachments")
    if isinstance(raw_attachments, list):
        for item in raw_attachments[:_MAX_ATTACHMENTS]:
            if not isinstance(item, dict):
                continue
            size = item.get("size")
            attachments.append(
                Attachment(
                    attachment_id=_optional_string(item.get("id")),
                    filename=_optional_string(item.get("filename")),
                    content_type=_optional_string(item.get("content_type")),
                    size=size if isinstance(size, int) and not isinstance(size, bool) else None,
                    inline=bool(item.get("is_inline")),
                )
            )

    from_name, from_email = senders[0]
    body = str(payload.get("body") or "")[:_MAX_BODY_CHARACTERS]
    return NormalizedEmail(
        provider="nylas",
        provider_message_id=message_id,
        from_email=from_email,
        from_name=from_name,
        to_email=account_email,
        subject=str(payload.get("subject") or "")[:998],
        text_body=_body_to_text(body),
        html_body=body or None,
        received_at=_epoch(payload.get("date")),
        in_reply_to=_first_header(payload, "in-reply-to"),
        references=_references(payload),
        thread_id=thread_id,
        attachments=tuple(attachments),
        raw_payload=dict(payload),
        sender_authentication=SenderAuthentication.UNKNOWN,
    )


def normalize_nylas_sent_message(payload: dict[str, Any]) -> SentEmail:
    """Convert a Nylas sent message to provider-observed reply evidence."""

    header_id = _first_header(payload, "message-id")
    if not header_id:
        raise NylasError("Nylas sent message is missing its Message-ID header")
    recipients: list[str] = []
    for field in ("to", "cc", "bcc"):
        for _name, address in _addresses(payload.get(field)):
            if address not in recipients:
                recipients.append(address)
    return SentEmail(
        provider="nylas",
        provider_message_id=header_id,
        recipients=tuple(recipients),
        sent_at=_epoch(payload.get("date")),
    )


def _optional_string(value: Any) -> str | None:
    return str(value) if value not in {None, ""} else None


class NylasProvider(EmailProvider):
    """Nylas REST adapter that accepts only proven replies to observed sends."""

    name = "nylas"
    requires_reply_proof = True

    def __init__(
        self,
        *,
        api_key: str,
        grant_id: str,
        account_email: str,
        base_url: str = "https://api.us.nylas.com/v3",
        timeout: float = 30,
        allow_insecure_local_http: bool = False,
    ) -> None:
        if not api_key:
            raise NylasError("Nylas API key is required")
        if not grant_id:
            raise NylasError("Nylas grant id is required")
        self.api_key = api_key
        self.grant_id = grant_id
        self.account_email = normalize_email_address(account_email)
        self.base_url = validate_api_base_url(
            base_url,
            variable="NYLAS_BASE_URL",
            allow_local_http=allow_insecure_local_http,
        )
        self.timeout = timeout
        self._opener = build_opener(_NoRedirectHandler)
        self._folder_ids: dict[str, str] = {}
        self._send_identities: dict[str, tuple[str, str | None, str | None]] = {}

    @property
    def _grant_path(self) -> str:
        return f"/grants/{quote(self.grant_id, safe='')}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        send: bool = False,
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        if params:
            url = f"{url}?{urlencode(params)}"
        data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode() if body else None
        request_headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": f"hermes-email-bridge/{__version__}",
        }
        request_headers.update(headers or {})
        request = Request(url, data=data, method=method, headers=request_headers)
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            self._raise_http(exc.code, send=send)
        except (TimeoutError, URLError):
            if send:
                raise AmbiguousSendError("Nylas send outcome is uncertain") from None
            raise RetryableProviderError("Nylas API request failed") from None
        if len(raw) > _MAX_RESPONSE_BYTES:
            if send:
                raise AmbiguousSendError("Nylas send response exceeded its safety bound")
            raise NylasError("Nylas API response exceeded its safety bound")
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            if send:
                raise AmbiguousSendError("Nylas send returned invalid JSON") from None
            raise NylasError("Nylas API returned invalid JSON") from None
        if not isinstance(decoded, dict):
            if send:
                raise AmbiguousSendError("Nylas send returned an unexpected response")
            raise NylasError("Nylas API returned an unexpected response")
        return decoded

    @staticmethod
    def _raise_http(status: int, *, send: bool) -> None:
        if send:
            if status in {408, 409} or 500 <= status <= 599:
                raise AmbiguousSendError(f"Nylas send outcome is uncertain (HTTP {status})")
            raise NylasError(f"Nylas send was rejected (HTTP {status})")
        if status in {408, 429} or 500 <= status <= 599:
            raise RetryableProviderError(f"Nylas API is temporarily unavailable (HTTP {status})")
        raise NylasError(f"Nylas API returned HTTP {status}")

    @staticmethod
    def _data_object(response: dict[str, Any]) -> dict[str, Any]:
        data = response.get("data")
        if not isinstance(data, dict):
            raise NylasError("Nylas API response is missing message data")
        return data

    def _system_folder(self, name: str) -> str:
        cached = self._folder_ids.get(name)
        if cached:
            return cached
        response = self._request("GET", f"{self._grant_path}/folders", params={"limit": 50})
        data = response.get("data")
        if not isinstance(data, list):
            raise NylasError("Nylas folders response is malformed")
        for item in data:
            if not isinstance(item, dict):
                continue
            folder_name = str(item.get("name") or "").strip().lower()
            folder_id = item.get("id")
            system_folder = item.get("system_folder")
            attributes = item.get("attributes")
            attribute_names = (
                {
                    str(attribute).strip().lstrip("\\").lower()
                    for attribute in attributes
                    if isinstance(attribute, str)
                }
                if isinstance(attributes, list)
                else set()
            )
            is_match = (
                isinstance(system_folder, str) and system_folder.strip().lower() == name
            ) or (
                system_folder is True
                and (
                    folder_name == name
                    or (isinstance(folder_id, str) and folder_id.strip().lower() == name)
                    or name in attribute_names
                )
            )
            if is_match and isinstance(folder_id, str) and folder_id:
                self._folder_ids[name] = folder_id
                return folder_id
        raise NylasError(f"Nylas system folder is missing: {name}")

    def _message(self, message_id: str) -> dict[str, Any]:
        response = self._request(
            "GET",
            f"{self._grant_path}/messages/{quote(message_id, safe='')}",
            params={"fields": "include_basic_headers"},
        )
        return self._data_object(response)

    def _poll_payloads(
        self,
        cursor: str | None,
        *,
        folder_name: str,
    ) -> tuple[list[dict[str, Any]], str | None]:
        params: dict[str, Any] = {
            "in": self._system_folder(folder_name),
            "limit": 20,
        }
        latest = datetime.fromisoformat(cursor.replace("Z", "+00:00")) if cursor else None
        if latest:
            params["received_after"] = int((latest - timedelta(seconds=1)).timestamp())
        page_token: str | None = None
        seen_tokens: set[str] = set()
        seen_messages: set[str] = set()
        messages: list[dict[str, Any]] = []
        for _page in range(_MAX_PAGES):
            if page_token:
                params["page_token"] = page_token
            response = self._request("GET", f"{self._grant_path}/messages", params=params)
            summaries = response.get("data")
            if not isinstance(summaries, list):
                raise NylasError("Nylas messages response is malformed")
            for summary in summaries:
                if not isinstance(summary, dict):
                    continue
                message_id = summary.get("id")
                if not isinstance(message_id, str) or not message_id or message_id in seen_messages:
                    continue
                seen_messages.add(message_id)
                detail = self._message(message_id)
                message_time = _epoch(detail.get("date"))
                messages.append(detail)
                if latest is None or message_time > latest:
                    latest = message_time
            raw_token = response.get("next_cursor")
            if not isinstance(raw_token, str) or not raw_token:
                break
            if raw_token in seen_tokens:
                raise NylasError("Nylas pagination cursor repeated")
            seen_tokens.add(raw_token)
            page_token = raw_token
        else:
            raise NylasError("Nylas poll exceeded the page safety limit")
        messages.sort(key=lambda item: _epoch(item.get("date")))
        next_cursor = latest.isoformat().replace("+00:00", "Z") if latest else cursor
        return messages, next_cursor

    def poll(self, cursor: str | None) -> PollResult:
        payloads, next_cursor = self._poll_payloads(cursor, folder_name="inbox")
        messages = tuple(
            normalize_nylas_message(payload, account_email=self.account_email)
            for payload in payloads
        )
        return PollResult(messages, next_cursor)

    def poll_sent(self, cursor: str | None) -> SentPollResult:
        payloads, next_cursor = self._poll_payloads(cursor, folder_name="sent")
        messages = tuple(normalize_nylas_sent_message(payload) for payload in payloads)
        return SentPollResult(messages, next_cursor)

    def get(self, message_id: str) -> NormalizedEmail:
        return normalize_nylas_message(
            self._message(message_id),
            account_email=self.account_email,
        )

    def reply(self, message: NormalizedEmail, text: str) -> str:
        recipient = normalize_email_address(message.from_email)
        operation_key = sha256(
            f"hermes-email-reply-v1\0{self.grant_id}\0{message.provider_message_id}".encode()
        ).hexdigest()
        subject = (
            message.subject
            if message.subject.lower().startswith("re:")
            else f"Re: {message.subject}"
        )
        response = self._request(
            "POST",
            f"{self._grant_path}/messages/send",
            params={"fields": "include_basic_headers"},
            body={
                "body": text,
                "is_plaintext": True,
                "reply_to_message_id": message.provider_message_id,
                "subject": subject,
                "to": [{"email": recipient}],
            },
            headers={"Idempotency-Key": operation_key},
            send=True,
        )
        data = self._data_object(response)
        sent_id = _first_header(data, "message-id") or str(data.get("id") or "")
        if not sent_id:
            raise AmbiguousSendError("Nylas send response is missing a message id")
        return sent_id

    def delivery_identity(
        self, operation_id: str, message_id: str
    ) -> tuple[str, str | None, str | None] | None:
        return self._send_identities.get(operation_id)

    def send(
        self,
        *,
        operation_id: str,
        to: str,
        subject: str,
        text: str | None,
        html: str | None,
    ) -> str:
        recipient = normalize_email_address(to)
        operation_key = sha256(
            f"hermes-email-send-v1\0{self.grant_id}\0{operation_id}".encode()
        ).hexdigest()
        response = self._request(
            "POST",
            f"{self._grant_path}/messages/send",
            params={"fields": "include_basic_headers"},
            body={
                "body": html if html is not None else text,
                "is_plaintext": html is None,
                "subject": subject,
                "to": [{"email": recipient}],
                "metadata": {"hermes_operation_id": operation_id},
            },
            headers={"Idempotency-Key": operation_key},
            send=True,
        )
        try:
            data = self._data_object(response)
        except NylasError:
            raise AmbiguousSendError(
                "Nylas accepted request but returned invalid evidence"
            ) from None
        sent_id = _first_header(data, "message-id") or str(data.get("id") or "")
        if not sent_id:
            raise AmbiguousSendError("Nylas send response is missing a message id")
        self._send_identities[operation_id] = (
            self.grant_id,
            _optional_string(data.get("id")),
            _first_header(data, "message-id"),
        )
        return sent_id
