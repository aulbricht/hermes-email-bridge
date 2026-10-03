from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from itertools import permutations
from pathlib import Path

import pytest

from hermes_email_bridge.delivery import DeliveryEvent, DeliveryStatus, DeliveryStore
from hermes_email_bridge.store import MappingStore

NOW = datetime(2026, 10, 2, tzinfo=UTC)


def event(
    status: DeliveryStatus = DeliveryStatus.DELIVERED,
    *,
    event_id: str = "event-1",
    operation_id: str | None = "operation-1",
    grant_id: str = "grant-1",
    message_id: str | None = "message-1",
    seconds: int = 0,
) -> DeliveryEvent:
    return DeliveryEvent(
        event_id=event_id,
        provider="nylas",
        grant_id=grant_id,
        status=status,
        occurred_at=NOW + timedelta(seconds=seconds),
        operation_id=operation_id,
        provider_message_id=message_id,
    )


def accept(store: DeliveryStore) -> None:
    store.record_acceptance(
        "nylas", "operation-1", grant_id="grant-1", provider_message_id="message-1", accepted_at=NOW
    )


def test_acceptance_is_awaiting_and_overdue_is_not_failure() -> None:
    with DeliveryStore() as store:
        accept(store)
        record = store.get("nylas", "operation-1")
        assert record is not None and record.status is DeliveryStatus.AWAITING
        assert store.health(now=NOW + timedelta(minutes=16))["awaiting_overdue"] == 1
        assert store.health(now=NOW + timedelta(minutes=9))["awaiting_overdue"] == 0


def test_idempotent_acceptance_preserves_terminal_and_acceptance_time() -> None:
    with DeliveryStore() as store:
        accept(store)
        store.apply_event(event())
        accept(store)
        record = store.get("nylas", "operation-1")
        assert record is not None and record.status is DeliveryStatus.DELIVERED
        assert record.accepted_at == NOW


def test_durable_event_duplicate_after_reopen(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    with DeliveryStore(path) as store:
        accept(store)
        assert not store.apply_event(event()).duplicate
    with DeliveryStore(path) as store:
        assert store.apply_event(event()).duplicate
        assert store.health()["counts"] == {"delivered": 1}


def test_adverse_evidence_is_order_independent() -> None:
    statuses = (
        DeliveryStatus.DELIVERED,
        DeliveryStatus.BOUNCED,
        DeliveryStatus.COMPLAINT,
        DeliveryStatus.REJECTED,
    )
    for ordering in permutations(statuses):
        with DeliveryStore() as store:
            accept(store)
            for status in ordering:
                store.apply_event(event(status, event_id=status, seconds=statuses.index(status)))
            record = store.get("nylas", "operation-1")
            assert record is not None and record.status is DeliveryStatus.COMPLAINT
            assert record.last_event_at == NOW + timedelta(seconds=3)


def test_event_before_acceptance_is_quarantined_then_reconciled() -> None:
    with DeliveryStore() as store:
        assert store.apply_event(event()).disposition == "quarantined"
        assert store.health()["quarantined_events"] == 1
        accept(store)
        record = store.get("nylas", "operation-1")
        assert record is not None and record.status is DeliveryStatus.DELIVERED
        assert store.health()["quarantined_events"] == 0
        assert store.apply_event(event()).disposition == "matched"


@pytest.mark.parametrize(
    "operation,grant,message",
    [
        ("unknown-operation", "grant-1", "message-1"),
        ("operation-1", "wrong-grant", "message-1"),
        ("operation-1", "grant-1", "wrong-message"),
        (None, "grant-1", "unknown-message"),
    ],
)
def test_conflicting_or_unknown_identity_is_quarantined(
    operation: str | None, grant: str, message: str
) -> None:
    with DeliveryStore() as store:
        accept(store)
        result = store.apply_event(
            event(operation_id=operation, grant_id=grant, message_id=message)
        )
        assert result.disposition == "quarantined"
        record = store.get("nylas", "operation-1")
        assert record is not None and record.status is DeliveryStatus.AWAITING


def test_two_identifiers_pointing_at_different_operations_is_quarantined() -> None:
    with DeliveryStore() as store:
        accept(store)
        store.record_acceptance(
            "nylas", "operation-2", grant_id="grant-1", provider_message_id="message-2"
        )
        assert store.apply_event(event(message_id="message-2")).disposition == "quarantined"


def test_metadata_can_enrich_rfc_only_acceptance() -> None:
    with DeliveryStore() as store:
        store.record_acceptance(
            "nylas", "operation-1", grant_id="grant-1", rfc_message_id="<original@example.com>"
        )
        assert store.apply_event(event()).disposition == "matched"
        record = store.get("nylas", "operation-1")
        assert record is not None and record.provider_message_id == "message-1"


def test_message_and_grant_can_correlate_without_metadata() -> None:
    with DeliveryStore() as store:
        accept(store)
        assert store.apply_event(event(operation_id=None)).disposition == "matched"


def test_rfc_id_correlation() -> None:
    with DeliveryStore() as store:
        store.record_acceptance(
            "nylas", "operation-1", grant_id="grant-1", rfc_message_id="<original@example.com>"
        )
        evidence = DeliveryEvent(
            event_id="event",
            provider="nylas",
            grant_id="grant-1",
            status=DeliveryStatus.BOUNCED,
            occurred_at=NOW,
            rfc_message_id="<original@example.com>",
        )
        assert store.apply_event(evidence).disposition == "matched"


def test_duplicate_event_id_with_changed_payload_fails_closed() -> None:
    with DeliveryStore() as store:
        accept(store)
        store.apply_event(event())
        with pytest.raises(ValueError, match="identity conflict"):
            store.apply_event(event(DeliveryStatus.BOUNCED))


def test_changed_acceptance_and_reused_message_fail_closed() -> None:
    with DeliveryStore() as store:
        accept(store)
        with pytest.raises(ValueError, match="identity changed"):
            store.record_acceptance("nylas", "operation-1", grant_id="different")
        with pytest.raises(ValueError, match="another operation"):
            store.record_acceptance(
                "nylas", "operation-2", grant_id="grant-1", provider_message_id="message-1"
            )


def test_shared_mapping_connection_keeps_schema_version() -> None:
    with MappingStore(":memory:") as mapping:
        before = mapping._connection.execute("PRAGMA user_version").fetchone()[0]
        with DeliveryStore(connection=mapping._connection, lock=mapping._lock) as delivery:
            accept(delivery)
            delivery.apply_event(event())
        assert mapping._connection.execute("PRAGMA user_version").fetchone()[0] == before
        assert (
            mapping._connection.execute("SELECT COUNT(*) FROM outbound_operations").fetchone()[0]
            == 0
        )


def test_caller_owned_transaction_rolls_back_acceptance() -> None:
    with sqlite3.connect(":memory:") as connection:
        store = DeliveryStore(connection=connection)
        connection.execute("BEGIN IMMEDIATE")
        store.record_acceptance("nylas", "operation-1", grant_id="grant-1", commit=False)
        assert connection.in_transaction
        connection.rollback()
        assert store.get("nylas", "operation-1") is None
        with pytest.raises(ValueError, match="active caller transaction"):
            store.record_acceptance("nylas", "operation-1", grant_id="grant-1", commit=False)


def test_multiple_connections_reject_changed_acceptance(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    with DeliveryStore(path) as first, DeliveryStore(path) as second:
        accept(first)
        with pytest.raises(ValueError):
            second.record_acceptance("nylas", "operation-1", grant_id="different")


def test_unknown_fields_cannot_store_content(tmp_path: Path) -> None:
    value = event().as_dict()
    value["body"] = "PRIVATE MESSAGE CONTENT"
    with pytest.raises(ValueError):
        DeliveryEvent.from_dict(value)
    path = tmp_path / "ledger.db"
    with DeliveryStore(path) as store:
        accept(store)
        store.apply_event(event())
        store.worker_poll(error_code="queue_error")
        assert store.health()["worker"]["error_code"] == "queue_error"
    assert b"PRIVATE MESSAGE CONTENT" not in path.read_bytes()
    with sqlite3.connect(path) as connection:
        columns = [
            row[1] for row in connection.execute("PRAGMA table_info(outbound_delivery_events)")
        ]
        assert "body" not in columns and "raw_payload" not in columns


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", 2),
        ("status", "awaiting"),
        ("operation_id", "bad operation"),
        ("occurred_at", "2026-10-02"),
    ],
)
def test_invalid_normalized_events(field: str, value: object) -> None:
    payload = event().as_dict()
    payload[field] = value
    with pytest.raises(ValueError):
        DeliveryEvent.from_dict(payload)
