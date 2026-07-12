"""AgentMail transport through Composio Proxy Execute."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote
from urllib.request import Request, build_opener

from .. import __version__
from .agentmail import AgentMailError, AgentMailProvider, _NoRedirectHandler
from .base import RetryableProviderError

_PROXY_URL = "https://backend.composio.dev/api/v3.1/tools/execute/proxy"
_MAX_RETRY_AFTER = 300.0


class ComposioAgentMailError(AgentMailError):
    """A non-retryable Composio transport or wrapper failure."""


class ComposioAgentMailProvider(AgentMailProvider):
    """Reuse AgentMail semantics while Composio injects its stored credential."""

    def __init__(
        self,
        *,
        api_key: str,
        connected_account_id: str,
        inbox_id: str,
        timeout: float = 30,
    ) -> None:
        values = (api_key, connected_account_id, inbox_id)
        if not all(values) or any(
            ord(character) < 32 or ord(character) == 127 for value in values for character in value
        ):
            raise ValueError("Composio API key, connected account, and inbox are required")
        self.api_key = api_key
        self.connected_account_id = connected_account_id
        self.inbox_id = inbox_id
        self.timeout = timeout
        self._opener = build_opener(_NoRedirectHandler)

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._validate_agentmail_request(method, path)
        parameters: list[dict[str, str]] = []
        for name, raw_value in (params or {}).items():
            values = raw_value if isinstance(raw_value, (list, tuple)) else [raw_value]
            parameters.extend(
                {"name": str(name), "value": str(value), "in": "query"} for value in values
            )
        proxy_body: dict[str, Any] = {
            "endpoint": f"/v0{path}",
            "method": method,
            "connected_account_id": self.connected_account_id,
        }
        if parameters:
            proxy_body["parameters"] = parameters
        if body is not None:
            proxy_body["body"] = body
        request = Request(
            _PROXY_URL,
            data=json.dumps(proxy_body).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"hermes-email-bridge/{__version__}",
                "x-api-key": self.api_key,
            },
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                decoded = json.loads(response.read())
        except HTTPError as exc:
            self._raise_status(exc.code, exc.headers)
        except (TimeoutError, URLError):
            raise RetryableProviderError("Composio proxy request failed") from None
        except json.JSONDecodeError:
            raise ComposioAgentMailError("Composio proxy returned invalid JSON") from None
        if not isinstance(decoded, dict):
            raise ComposioAgentMailError("Composio proxy returned an unexpected response")
        status = decoded.get("status")
        if isinstance(status, bool) or not isinstance(status, int):
            raise ComposioAgentMailError("Composio proxy response is malformed")
        headers = decoded.get("headers")
        response_headers = headers if isinstance(headers, Mapping) else {}
        if status < 200 or status >= 300:
            self._raise_status(status, response_headers, upstream=True)
        data = decoded.get("data")
        if not isinstance(data, dict):
            raise ComposioAgentMailError("Composio upstream response is malformed")
        return data

    def _validate_agentmail_request(self, method: str, path: str) -> None:
        inbox = quote(self.inbox_id, safe="")
        collection = f"/inboxes/{inbox}/messages"
        if method == "GET" and path == collection:
            return
        prefix = f"{collection}/"
        if not path.startswith(prefix):
            raise ComposioAgentMailError("unsupported AgentMail proxy path")
        remainder = path.removeprefix(prefix)
        if not remainder or ("/" in remainder and not remainder.endswith("/reply")):
            raise ComposioAgentMailError("unsupported AgentMail proxy path")
        message_part = remainder.removesuffix("/reply")
        decoded_message = unquote(message_part)
        if (
            not message_part
            or decoded_message.startswith("/")
            or decoded_message.endswith("/")
            or "//" in decoded_message
            or "\\" in decoded_message
            or any(segment in {".", ".."} for segment in decoded_message.split("/"))
            or any(ord(character) < 32 or ord(character) == 127 for character in decoded_message)
            or quote(decoded_message, safe="") != message_part
        ):
            raise ComposioAgentMailError("unsupported AgentMail proxy path")
        if method == "GET" and remainder == message_part:
            return
        if method == "POST" and remainder == f"{message_part}/reply":
            return
        raise ComposioAgentMailError("unsupported AgentMail proxy request")

    @staticmethod
    def _raise_status(
        status: int,
        headers: Any,
        *,
        upstream: bool = False,
    ) -> None:
        source = "AgentMail through Composio" if upstream else "Composio proxy"
        if status in {408, 429} or 500 <= status <= 599:
            raise RetryableProviderError(
                f"{source} temporarily unavailable (HTTP {status})",
                retry_after=_retry_after(headers),
            ) from None
        raise ComposioAgentMailError(f"{source} returned HTTP {status}") from None


def _retry_after(headers: Any) -> float | None:
    if not hasattr(headers, "items"):
        return None
    raw = next(
        (str(value) for key, value in headers.items() if str(key).lower() == "retry-after"),
        None,
    )
    if raw is None:
        return None
    try:
        seconds = float(raw)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(raw)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            seconds = (parsed - datetime.now(UTC)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return None
    if 0 <= seconds <= _MAX_RETRY_AFTER:
        return seconds
    return None
