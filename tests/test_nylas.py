from __future__ import annotations

from typing import Any

import pytest

from hermes_email_bridge.config import ConfigError, Settings
from hermes_email_bridge.models import SenderAuthentication
from hermes_email_bridge.providers.base import AmbiguousSendError
from hermes_email_bridge.providers.nylas import (
    NylasError,
    NylasProvider,
    normalize_nylas_message,
    normalize_nylas_sent_message,
)

ACCOUNT = "mailbox@mail.example.test"


def _payload(
    *,
    message_id: str = "message-1",
    sender: str = "allowed@example.test",
    recipient: str = ACCOUNT,
) -> dict[str, Any]:
    return {
        "id": message_id,
        "thread_id": "thread-1",
        "from": [{"name": "Allowed Sender", "email": sender}],
        "to": [{"email": recipient}],
        "cc": [],
        "bcc": [],
        "subject": "Re: Request",
        "body": (
            "<style>hidden</style><p>Hello <b>there</b>.</p>"
            "<script>also hidden</script><p>fmp://record/123</p>"
        ),
        "date": 1_784_069_200,
        "headers": [
            {"name": "Message-ID", "value": "<inbound@example.test>"},
            {"name": "In-Reply-To", "value": "<outbound@example.test>"},
            {
                "name": "References",
                "value": "<first@example.test> <outbound@example.test>",
            },
        ],
        "attachments": [
            {
                "id": "attachment-1",
                "filename": "notes.txt",
                "content_type": "text/plain",
                "size": 12,
                "is_inline": False,
            }
        ],
    }


def test_normalizes_bounded_nylas_message_without_trusting_headers() -> None:
    payload = _payload()
    payload["headers"].append(
        {
            "name": "Authentication-Results",
            "value": "untrusted.example; dkim=pass; dmarc=pass",
        }
    )
    message = normalize_nylas_message(payload, account_email=ACCOUNT)

    assert message.provider == "nylas"
    assert message.from_email == "allowed@example.test"
    assert message.to_email == ACCOUNT
    assert message.text_body == "Hello there.\n\nfmp://record/123"
    assert "hidden" not in message.text_body
    assert message.in_reply_to == "<outbound@example.test>"
    assert message.references[-1] == "<outbound@example.test>"
    assert message.attachments[0].filename == "notes.txt"
    assert message.sender_authentication is SenderAuthentication.UNKNOWN


@pytest.mark.parametrize(
    "mutation",
    [
        {"to": [{"email": "other@example.test"}]},
        {"to": [{"email": ACCOUNT}, {"email": "other@example.test"}]},
        {"cc": [{"email": "other@example.test"}]},
        {"from": []},
        {
            "from": [
                {"email": "first@example.test"},
                {"email": "second@example.test"},
            ]
        },
    ],
)
def test_normalizer_rejects_ambiguous_identity_or_recipient(mutation: dict[str, Any]) -> None:
    payload = _payload()
    payload.update(mutation)
    with pytest.raises(NylasError):
        normalize_nylas_message(payload, account_email=ACCOUNT)


def test_sent_message_uses_rfc_message_id_as_reply_proof() -> None:
    payload = _payload(sender=ACCOUNT, recipient="allowed@example.test")
    payload["headers"] = [
        {"name": "Message-ID", "value": "<outbound@example.test>"}
    ]
    sent = normalize_nylas_sent_message(payload)
    assert sent.provider_message_id == "<outbound@example.test>"
    assert sent.recipients == ("allowed@example.test",)


class StubNylasProvider(NylasProvider):
    def __init__(self) -> None:
        super().__init__(api_key="test", grant_id="grant-1", account_email=ACCOUNT)
        self.requests: list[tuple[str, str, dict[str, Any] | None]] = []

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
        del body, headers, send
        self.requests.append((method, path, params))
        if path.endswith("/folders"):
            return {
                "data": [
                    {
                        "id": "inbox",
                        "name": "Inbox",
                        "system_folder": True,
                        "attributes": ["\\Inbox"],
                    },
                    {
                        "id": "sent",
                        "name": "Sent",
                        "system_folder": True,
                        "attributes": ["\\Sent"],
                    },
                ]
            }
        if path.endswith("/messages"):
            return {"data": [{"id": "message-1", "date": 1_784_069_200}]}
        return {"data": _payload()}


def test_provider_polls_only_the_isolated_inbox_with_overlap() -> None:
    provider = StubNylasProvider()
    result = provider.poll("2026-07-13T12:00:00Z")

    assert result.messages[0].provider_message_id == "message-1"
    list_request = next(item for item in provider.requests if item[1].endswith("/messages"))
    assert list_request[2]
    assert list_request[2]["in"] == "inbox"
    assert list_request[2]["received_after"] == 1_783_943_999
    assert "select" not in list_request[2]


def test_provider_accepts_named_system_folder_shape() -> None:
    class NamedSystemFolderProvider(StubNylasProvider):
        def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
            if path.endswith("/folders"):
                return {
                    "data": [
                        {"id": "folder-inbox", "system_folder": "inbox"},
                        {"id": "folder-sent", "system_folder": "sent"},
                    ]
                }
            return super()._request(method, path, **kwargs)

    provider = NamedSystemFolderProvider()
    assert provider._system_folder("inbox") == "folder-inbox"


def test_reply_preserves_custom_scheme_and_uses_stable_idempotency_key() -> None:
    class RecordingProvider(NylasProvider):
        def __init__(self) -> None:
            super().__init__(api_key="test", grant_id="grant-1", account_email=ACCOUNT)
            self.calls: list[tuple[dict[str, Any], dict[str, str]]] = []

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
            assert method == "POST"
            assert path.endswith("/messages/send")
            assert params == {"fields": "include_basic_headers"}
            assert send is True
            assert body is not None and headers is not None
            self.calls.append((body, headers))
            return {
                "data": {
                    "id": "sent-1",
                    "headers": [
                        {"name": "Message-ID", "value": "<reply@example.test>"}
                    ],
                }
            }

    provider = RecordingProvider()
    message = normalize_nylas_message(_payload(), account_email=ACCOUNT)
    text = "Open fmp://record/123"
    assert provider.reply(message, text) == "<reply@example.test>"
    assert provider.reply(message, text) == "<reply@example.test>"
    first_body, first_headers = provider.calls[0]
    assert first_body["body"] == text
    assert first_body["is_plaintext"] is True
    assert first_body["to"] == [{"email": "allowed@example.test"}]
    assert "from" not in first_body
    assert first_headers["Idempotency-Key"] == provider.calls[1][1]["Idempotency-Key"]


def test_nylas_settings_require_explicit_identity_and_sender_allowlist() -> None:
    values = {
        "EMAIL_BRIDGE_PROVIDER": "nylas",
        "NYLAS_API_KEY": "test-key",
        "NYLAS_GRANT_ID": "grant-1",
        "NYLAS_ACCOUNT_EMAIL": ACCOUNT,
        "EMAIL_BRIDGE_ALLOWED_SENDERS": "First@Example.Test,second@example.test",
    }
    settings = Settings.from_env(values)
    assert settings.require_nylas() == ("test-key", "grant-1", ACCOUNT)
    assert settings.allowed_senders == frozenset(
        {"first@example.test", "second@example.test"}
    )
    assert settings.logical_provider() == "nylas"
    values.pop("EMAIL_BRIDGE_ALLOWED_SENDERS")
    with pytest.raises(ConfigError, match="EMAIL_BRIDGE_ALLOWED_SENDERS"):
        Settings.from_env(values).require_nylas()


@pytest.mark.parametrize(
    "base_url",
    [
        "http://api.example.test/v3",
        "file:///tmp/provider",
        "https://user:secret@api.example.test/v3",
        "https://api.example.test/v3?token=value",
    ],
)
def test_nylas_provider_rejects_unsafe_base_urls(base_url: str) -> None:
    with pytest.raises(ConfigError):
        NylasProvider(
            api_key="secret",
            grant_id="grant-1",
            account_email=ACCOUNT,
            base_url=base_url,
        )


def test_send_transport_ambiguity_is_explicit() -> None:
    class AmbiguousProvider(NylasProvider):
        def _request(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            raise AmbiguousSendError("uncertain")

    provider = AmbiguousProvider(api_key="test", grant_id="grant-1", account_email=ACCOUNT)
    with pytest.raises(AmbiguousSendError, match="uncertain"):
        provider.reply(normalize_nylas_message(_payload(), account_email=ACCOUNT), "reply")
