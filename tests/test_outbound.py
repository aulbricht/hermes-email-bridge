from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hermes_email_bridge.delivery import DeliveryEvent, DeliveryStatus
from hermes_email_bridge.models import NormalizedEmail, PollResult, SentPollResult
from hermes_email_bridge.outbound import OutboundResult, OutboundService
from hermes_email_bridge.providers.base import AmbiguousSendError, EmailProvider
from hermes_email_bridge.store import MappingStore


class RecordingProvider(EmailProvider):
    name = "fake"

    def __init__(self, failure: Exception | None = None) -> None:
        self.failure = failure
        self.calls: list[dict[str, str | None]] = []

    def poll(self, cursor: str | None) -> PollResult:
        return PollResult((), cursor)

    def poll_sent(self, cursor: str | None) -> SentPollResult:
        return SentPollResult((), cursor)

    def get(self, message_id: str) -> NormalizedEmail:
        raise KeyError(message_id)

    def reply(self, message: NormalizedEmail, text: str) -> str:
        raise NotImplementedError

    def send(
        self,
        *,
        operation_id: str,
        to: str,
        subject: str,
        text: str | None,
        html: str | None,
    ) -> str:
        self.calls.append(
            {
                "operation_id": operation_id,
                "to": to,
                "subject": subject,
                "text": text,
                "html": html,
            }
        )
        if self.failure:
            raise self.failure
        return "sent-1"


def _send(service: OutboundService, operation_id: str = "operation-1") -> OutboundResult:
    return service.send(
        operation_id=operation_id,
        to="recipient@example.test",
        subject="Subject",
        text="Open fmp://record/123",
    )


class TrackedProvider(RecordingProvider):
    def delivery_identity(self, operation_id: str, message_id: str) -> tuple[str, str, str]:
        return "grant-1", "provider-1", "<sent@example.test>"


def test_accepted_operation_records_identity_and_duplicate_reads_terminal_evidence() -> None:
    provider = TrackedProvider()
    with MappingStore(":memory:") as store:
        service = OutboundService(provider=provider, store=store)
        assert _send(service).delivery_state == "awaiting"
        record = service.delivery.get("fake", "operation-1")
        assert record and record.provider_message_id == "provider-1"
        assert record.rfc_message_id == "<sent@example.test>"
        service.delivery.apply_event(
            DeliveryEvent(
                "event-1",
                "fake",
                "grant-1",
                DeliveryStatus.DELIVERED,
                datetime.now(UTC),
                operation_id="operation-1",
                provider_message_id="provider-1",
            )
        )
        result = _send(service)
        assert result.duplicate and result.delivery_state == "delivered"
        assert len(provider.calls) == 1


def test_atomic_acceptance_rolls_back_journal_on_invalid_identity() -> None:
    with MappingStore(":memory:") as store:
        store.claim_outbound_operation("fake", "operation-1", "hash")
        with pytest.raises(ValueError):
            store.set_outbound_accepted("fake", "operation-1", "message", ("", "p", None))
        row = store._connection.execute("SELECT state FROM outbound_operations").fetchone()
        assert row and row["state"] == "pending"
        assert (
            store._connection.execute("SELECT COUNT(*) FROM outbound_delivery").fetchone()[0] == 0
        )


def test_outbound_operation_is_journaled_and_duplicate_returns_prior_result() -> None:
    provider = RecordingProvider()
    with MappingStore(":memory:") as store:
        service = OutboundService(provider=provider, store=store)
        first = _send(service)
        duplicate = _send(service)
        assert first.provider_message_id == "sent-1"
        assert first.duplicate is False
        assert duplicate.provider_message_id == "sent-1"
        assert duplicate.duplicate is True
        assert len(provider.calls) == 1
        row = store._connection.execute(
            "SELECT payload_hash, state FROM outbound_operations"
        ).fetchone()
        assert row is not None and row["state"] == "sent"
        assert "recipient" not in row["payload_hash"]


def test_operation_id_cannot_be_reused_for_different_payload() -> None:
    provider = RecordingProvider()
    with MappingStore(":memory:") as store:
        service = OutboundService(provider=provider, store=store)
        _send(service)
        with pytest.raises(ValueError, match="different payload"):
            service.send(
                operation_id="operation-1",
                to="recipient@example.test",
                subject="Changed",
                text="body",
            )
        assert len(provider.calls) == 1


def test_ambiguous_send_becomes_uncertain_and_never_retries() -> None:
    provider = RecordingProvider(AmbiguousSendError("uncertain"))
    with MappingStore(":memory:") as store:
        service = OutboundService(provider=provider, store=store)
        with pytest.raises(AmbiguousSendError, match="uncertain"):
            _send(service)
        with pytest.raises(AmbiguousSendError, match="automatic retry suppressed"):
            _send(service)
        assert len(provider.calls) == 1
        row = store._connection.execute("SELECT state FROM outbound_operations").fetchone()
        assert row is not None and row["state"] == "uncertain"


def test_explicit_failure_is_terminal() -> None:
    provider = RecordingProvider(RuntimeError("rejected"))
    with MappingStore(":memory:") as store:
        service = OutboundService(provider=provider, store=store)
        with pytest.raises(RuntimeError, match="rejected"):
            _send(service)
        with pytest.raises(RuntimeError, match="previously failed"):
            _send(service)
        assert len(provider.calls) == 1


def test_concurrent_identical_sends_contact_provider_once() -> None:
    provider = RecordingProvider()
    with MappingStore(":memory:") as store:
        service = OutboundService(provider=provider, store=store)
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _value: _send(service), range(8)))
        assert len(provider.calls) == 1
        assert sum(not result.duplicate for result in results) == 1


def test_additive_outbound_table_keeps_schema_v3_rollback_compatible(tmp_path: Path) -> None:
    path = str(tmp_path / "bridge.db")
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 3")
    with MappingStore(path) as store:
        table = store._connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'outbound_operations'"
        ).fetchone()
        assert table is not None
        assert store._connection.execute("PRAGMA user_version").fetchone()[0] == 3
