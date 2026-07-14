import threading
from datetime import UTC
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from hermes_email_bridge.config import (
    ISOLATED_HERMES_COMMAND,
    ConfigError,
    Settings,
)
from hermes_email_bridge.models import SenderAuthentication
from hermes_email_bridge.providers.agentmail import (
    AgentMailError,
    AgentMailProvider,
    normalize_agentmail_message,
    normalize_agentmail_sent_message,
)
from hermes_email_bridge.store import MappingStore


def test_normalizes_agentmail_message() -> None:
    message = normalize_agentmail_message(
        {
            "inbox_id": "bridge@agentmail.to",
            "message_id": "<incoming@example.com>",
            "thread_id": "thd_123",
            "from_": ["Ada Lovelace <ada@example.com>"],
            "to": ["bridge@agentmail.to"],
            "subject": "Re: Analysis",
            "text": "quoted history",
            "extracted_text": "The new reply",
            "html": "<p>The new reply</p>",
            "timestamp": "2026-07-09T12:00:00Z",
            "in_reply_to": "<outbound@agentmail.to>",
            "references": ["<first@agentmail.to>", "<outbound@agentmail.to>"],
            "attachments": [
                {
                    "attachment_id": "att_1",
                    "filename": "notes.txt",
                    "content_type": "text/plain",
                    "size": 12,
                    "inline": False,
                }
            ],
        }
    )

    assert message.provider == "agentmail"
    assert message.from_name == "Ada Lovelace"
    assert message.from_email == "ada@example.com"
    assert message.text_body == "The new reply"
    assert message.received_at.tzinfo == UTC
    assert message.references[-1] == "<outbound@agentmail.to>"
    assert message.attachments[0].filename == "notes.txt"
    assert message.sender_authentication is SenderAuthentication.UNKNOWN


def test_raw_authentication_results_header_is_never_trusted() -> None:
    message = normalize_agentmail_message(
        {
            "message_id": "message-1",
            "from": "attacker@example.com",
            "headers": {"Authentication-Results": "mx.attacker; dkim=pass; dmarc=pass"},
        }
    )
    assert message.sender_authentication is SenderAuthentication.UNKNOWN


def test_normalizes_trusted_sent_recipients_across_to_cc_bcc() -> None:
    message = normalize_agentmail_sent_message(
        {
            "message_id": "sent-1",
            "to": ["To Person <to@example.test>"],
            "cc": ["CC@example.test", "not-an-address"],
            "bcc": "bcc@example.test",
            "timestamp": "2026-07-11T12:00:00Z",
        }
    )
    assert message.provider == "agentmail"
    assert message.recipients == (
        "to@example.test",
        "cc@example.test",
        "bcc@example.test",
    )


def test_sent_message_without_provider_timestamp_fails_closed() -> None:
    with pytest.raises(AgentMailError, match="timestamp"):
        normalize_agentmail_sent_message(
            {
                "message_id": "old-sent-message",
                "to": ["person@example.test"],
            }
        )


class StubAgentMailProvider(AgentMailProvider):
    def __init__(self, detail_labels: list[str] | None = None) -> None:
        super().__init__(api_key="test", inbox_id="bridge@agentmail.to")
        self.detail_labels = detail_labels

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if path.endswith("/messages"):
            return {
                "messages": [
                    {"message_id": "message-1", "labels": ["received"]},
                    {"message_id": "message-2", "labels": ["unauthenticated"]},
                ]
            }
        payload: dict[str, Any] = {
            "message_id": "message-1",
            "from": "person@example.com",
            "to": ["bridge@agentmail.to"],
            "text": "hello",
            "timestamp": "2026-07-09T12:00:00Z",
        }
        if self.detail_labels is not None:
            payload["labels"] = self.detail_labels
        return payload


def test_poll_received_classification_is_authenticated() -> None:
    messages = StubAgentMailProvider().poll(None).messages
    assert len(messages) == 1
    assert messages[0].sender_authentication is SenderAuthentication.AUTHENTICATED


def test_api_unauthenticated_label_overrides_received_assumption() -> None:
    messages = StubAgentMailProvider(["unauthenticated"]).poll(None).messages
    assert messages[0].sender_authentication is SenderAuthentication.UNAUTHENTICATED


class StubSentAgentMailProvider(AgentMailProvider):
    def __init__(self) -> None:
        super().__init__(api_key="test", inbox_id="bridge@agentmail.to")

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if path.endswith("/messages"):
            assert params and params["labels"] == ["sent"]
            return {"messages": [{"message_id": "sent-1", "labels": ["sent"]}]}
        return {
            "message_id": "sent-1",
            "labels": ["sent"],
            "from": "bridge@agentmail.to",
            "to": ["to@example.test"],
            "cc": ["cc@example.test"],
            "bcc": ["bcc@example.test"],
            "timestamp": "2026-07-11T12:00:00Z",
        }


def test_direct_provider_polls_trusted_sent_recipient_metadata() -> None:
    result = StubSentAgentMailProvider().poll_sent(None)
    assert result.cursor == "2026-07-11T12:00:00Z"
    assert result.messages[0].recipients == (
        "to@example.test",
        "cc@example.test",
        "bcc@example.test",
    )


def test_direct_reply_targets_only_authenticated_from_address() -> None:
    class RecordingProvider(AgentMailProvider):
        def __init__(self) -> None:
            super().__init__(api_key="test", inbox_id="bridge@agentmail.test")
            self.body: dict[str, Any] | None = None

        def _request(
            self,
            method: str,
            path: str,
            *,
            params: dict[str, Any] | None = None,
            body: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            self.body = body
            return {"message_id": "reply-1"}

    message = normalize_agentmail_message(
        {
            "message_id": "inbound-1",
            "from": "Allowed <person@example.test>",
            "to": ["bridge@agentmail.test"],
            "cc": ["attacker-cc@example.test"],
            "bcc": ["attacker-bcc@example.test"],
            "reply_to": ["attacker-reply@example.test"],
            "timestamp": "2026-07-11T12:00:00Z",
        },
        sender_authentication=SenderAuthentication.AUTHENTICATED,
    )
    provider = RecordingProvider()
    with MappingStore(":memory:") as store:
        store.add_allowed_address("agentmail", message.from_email)
        assert store.is_allowed("agentmail", message.from_email)
        assert provider.reply(message, "safe reply") == "reply-1"
    assert provider.body == {
        "text": "safe reply",
        "to": ["person@example.test"],
        "reply_all": False,
    }


def test_unauthenticated_event_cannot_be_upgraded_by_api_received_label() -> None:
    provider = StubAgentMailProvider(["received"])
    message = provider.parse_webhook(
        {
            "event_type": "message.unauthenticated",
            "message": {
                "inbox_id": "bridge@agentmail.to",
                "message_id": "message-1",
                "from": "attacker@example.com",
                "to": ["bridge@agentmail.to"],
            },
        }
    )
    assert message and message.sender_authentication is SenderAuthentication.UNAUTHENTICATED


def test_webhook_ignores_non_received_events() -> None:
    provider = AgentMailProvider(api_key="test", inbox_id="bridge@agentmail.to")
    assert provider.parse_webhook({"event_type": "message.sent"}) is None


def test_webhook_rejects_another_inbox() -> None:
    provider = AgentMailProvider(api_key="test", inbox_id="bridge@agentmail.to")
    with pytest.raises(AgentMailError, match="configured inbox"):
        provider.parse_webhook(
            {
                "event_type": "message.received",
                "message": {"inbox_id": "other@agentmail.to", "message_id": "x"},
            }
        )


def test_webhook_accepts_email_recipient_when_payload_uses_internal_inbox_id() -> None:
    provider = AgentMailProvider(api_key="test", inbox_id="bridge@agentmail.to")
    message = provider.parse_webhook(
        {
            "event_type": "message.received",
            "message": {
                "inbox_id": "inbox_internal_123",
                "message_id": "<message@example.com>",
                "from_": ["person@example.com"],
                "to": ["bridge@agentmail.to"],
                "text": "hello",
                "timestamp": "2026-07-09T12:00:00Z",
            },
        }
    )
    assert message and message.provider_message_id == "<message@example.com>"
    assert message.sender_authentication is SenderAuthentication.AUTHENTICATED


def test_webhook_marks_unauthenticated_event_as_unauthenticated() -> None:
    provider = AgentMailProvider(api_key="test", inbox_id="bridge@agentmail.to")
    message = provider.parse_webhook(
        {
            "event_type": "message.received.unauthenticated",
            "message": {
                "inbox_id": "bridge@agentmail.to",
                "message_id": "message-1",
                "from": "attacker@example.com",
                "to": ["bridge@agentmail.to"],
                "text": "spoof",
            },
        }
    )
    assert message and message.sender_authentication is SenderAuthentication.UNAUTHENTICATED


@pytest.mark.parametrize(
    "base_url",
    [
        "http://api.agentmail.to/v0",
        "file:///tmp/agentmail",
        "gopher://api.agentmail.to/v0",
        "https://user:secret@api.agentmail.to/v0",
        "https://api.agentmail.to/v0?key=value",
        "https://api.agentmail.to/v0#fragment",
    ],
)
def test_provider_rejects_unsafe_base_urls(base_url: str) -> None:
    with pytest.raises(ConfigError):
        AgentMailProvider(api_key="secret", inbox_id="inbox", base_url=base_url)


def test_local_http_requires_explicit_loopback_override() -> None:
    with pytest.raises(ConfigError):
        AgentMailProvider(api_key="secret", inbox_id="inbox", base_url="http://127.0.0.1:8080/v0")
    provider = AgentMailProvider(
        api_key="secret",
        inbox_id="inbox",
        base_url="http://[::1]:8080/v0",
        allow_insecure_local_http=True,
    )
    assert provider.base_url == "http://[::1]:8080/v0"


def test_settings_reject_remote_http_and_defaults_raw_storage_off() -> None:
    with pytest.raises(ConfigError, match="must use HTTPS"):
        Settings.from_env({"AGENTMAIL_BASE_URL": "http://api.agentmail.to/v0"})
    settings = Settings.from_env({})
    assert settings.store_raw is False
    assert settings.allow_subject_resume is False


def test_live_replies_require_exact_isolated_protocol_wrapper() -> None:
    live = {
        "EMAIL_BRIDGE_SEND_REPLIES": "true",
        "EMAIL_BRIDGE_DRY_RUN": "false",
    }
    with pytest.raises(ConfigError, match="exact isolated Hermes protocol wrapper"):
        Settings.from_env(live)
    with pytest.raises(ConfigError, match="exact isolated Hermes protocol wrapper"):
        Settings.from_env({**live, "HERMES_COMMAND": "hermes chat --quiet --source tool"})
    settings = Settings.from_env({**live, "HERMES_COMMAND": ISOLATED_HERMES_COMMAND})
    assert settings.hermes_command == ISOLATED_HERMES_COMMAND


def test_legacy_command_remains_available_only_when_delivery_cannot_happen() -> None:
    assert Settings.from_env({}).hermes_command.startswith("hermes chat")
    assert Settings.from_env(
        {"EMAIL_BRIDGE_SEND_REPLIES": "true", "EMAIL_BRIDGE_DRY_RUN": "true"}
    ).dry_run


def test_settings_normalize_and_validate_reply_domains() -> None:
    settings = Settings.from_env({"EMAIL_BRIDGE_REPLY_DOMAINS": "@Example.COM,43560.com"})
    assert settings.reply_domains == frozenset({"example.com", "43560.com"})
    with pytest.raises(ConfigError, match="comma-separated email domains"):
        Settings.from_env({"EMAIL_BRIDGE_REPLY_DOMAINS": "example.com,evil@example.com"})


def test_composio_settings_require_only_key_account_and_inbox() -> None:
    settings = Settings.from_env(
        {
            "EMAIL_BRIDGE_PROVIDER": "composio-agentmail",
            "EMAIL_BRIDGE_COMPOSIO_API_KEY": "test-key",
            "COMPOSIO_AGENT_MAIL_CONNECTED_ACCOUNT_ID": "ca_test",
            "COMPOSIO_AGENT_MAIL_INBOX_ID": "bridge@example.test",
        }
    )
    assert settings.require_composio_agentmail() == (
        "test-key",
        "ca_test",
        "bridge@example.test",
    )
    assert settings.logical_provider() == "agentmail"
    with pytest.raises(ConfigError, match="EMAIL_BRIDGE_COMPOSIO_API_KEY"):
        Settings.from_env(
            {"EMAIL_BRIDGE_PROVIDER": "composio-agentmail"}
        ).require_composio_agentmail()
    with pytest.raises(ConfigError, match="EMAIL_BRIDGE_COMPOSIO_API_KEY"):
        Settings.from_env(
            {
                "EMAIL_BRIDGE_PROVIDER": "composio-agentmail",
                "COMPOSIO_API_KEY": "must-not-be-used-by-the-bridge",
                "COMPOSIO_AGENT_MAIL_CONNECTED_ACCOUNT_ID": "ca_test",
                "COMPOSIO_AGENT_MAIL_INBOX_ID": "bridge@example.test",
            }
        ).require_composio_agentmail()


def test_agentmail_redirect_is_rejected_before_following() -> None:
    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/stolen")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            pass

    with HTTPServer(("127.0.0.1", 0), RedirectHandler) as server:
        thread = threading.Thread(target=server.handle_request)
        thread.start()
        provider = AgentMailProvider(
            api_key="secret",
            inbox_id="inbox",
            base_url=f"http://127.0.0.1:{server.server_port}/v0",
            allow_insecure_local_http=True,
        )
        with pytest.raises(AgentMailError, match="HTTP 302"):
            provider._request("GET", "/redirect")
        thread.join(timeout=2)
        assert not thread.is_alive()
