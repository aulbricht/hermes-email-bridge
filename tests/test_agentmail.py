from datetime import UTC

import pytest

from hermes_email_bridge.providers.agentmail import (
    AgentMailError,
    AgentMailProvider,
    normalize_agentmail_message,
)


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
