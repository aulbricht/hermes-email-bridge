from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from hermes_email_bridge.delivery import DeliveryEvent, DeliveryStatus, DeliveryStore
from hermes_email_bridge.delivery_worker import DeliveryWorker


class FakeQueue:
    def __init__(self, messages: list[dict[str, Any]]) -> None:
        self.messages = messages
        self.deleted: list[str] = []
        self.fail_delete = False
        self.fail_receive = False

    def receive_message(self, **kwargs: Any) -> dict[str, Any]:
        assert kwargs["WaitTimeSeconds"] == 20
        if self.fail_receive:
            raise RuntimeError("sensitive AWS credentials in exception")
        return {"Messages": self.messages}

    def delete_message(self, **kwargs: Any) -> None:
        if self.fail_delete:
            raise RuntimeError("sensitive deletion error")
        self.deleted.append(kwargs["ReceiptHandle"])

    def get_queue_attributes(self, **kwargs: Any) -> dict[str, Any]:
        return {"Attributes": {"ApproximateNumberOfMessages": "3"}}


def message(*, grant_id: str = "grant-1", receipt: str = "receipt-1") -> dict[str, Any]:
    event = DeliveryEvent(
        event_id="event-1",
        provider="nylas",
        grant_id=grant_id,
        status=DeliveryStatus.DELIVERED,
        occurred_at=datetime.now(UTC),
        operation_id="operation-1",
        provider_message_id="message-1",
    )
    return {"Body": json.dumps(event.as_dict()), "ReceiptHandle": receipt}


def test_committed_evidence_precedes_delete_and_survives_failure(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    queue = FakeQueue([message()])
    queue.fail_delete = True
    with DeliveryStore(path) as store:
        store.record_acceptance(
            "nylas", "operation-1", grant_id="grant-1", provider_message_id="message-1"
        )
        worker = DeliveryWorker(
            store=store,
            client=queue,
            queue_url="https://sqs.example/queue",
            grant_id="grant-1",
            emit=lambda _: None,
        )
        assert worker.poll_once()["failed"] == 1
        assert queue.deleted == []
    queue.fail_delete = False
    with DeliveryStore(path) as store:
        worker = DeliveryWorker(
            store=store,
            client=queue,
            queue_url="https://sqs.example/queue",
            grant_id="grant-1",
            emit=lambda _: None,
        )
        assert worker.poll_once()["duplicates"] == 1
        assert queue.deleted == ["receipt-1"]


def test_unknown_event_is_durably_quarantined_then_deleted() -> None:
    queue = FakeQueue([message()])
    with DeliveryStore() as store:
        worker = DeliveryWorker(
            store=store,
            client=queue,
            queue_url="https://sqs.example/queue",
            grant_id="grant-1",
            emit=lambda _: None,
        )
        assert worker.poll_once()["quarantined"] == 1
        assert store.health()["quarantined_events"] == 1
        assert queue.deleted == ["receipt-1"]
        assert worker.health()["queue"]["ApproximateNumberOfMessages"] == 3


def test_bad_messages_stay_for_dlq_and_do_not_log_content() -> None:
    queue = FakeQueue(
        [
            {"Body": "PRIVATE MESSAGE CONTENT", "ReceiptHandle": "private-receipt"},
            message(grant_id="wrong-grant"),
        ]
    )
    output: list[dict[str, Any]] = []
    with DeliveryStore() as store:
        worker = DeliveryWorker(
            store=store,
            client=queue,
            queue_url="https://sqs.example/queue",
            grant_id="grant-1",
            emit=output.append,
        )
        assert worker.poll_once()["failed"] == 2
        assert queue.deleted == []
        assert store.health()["quarantined_events"] == 0
        assert store.health()["worker"]["error_code"] == "event_error"
    assert "PRIVATE" not in json.dumps(output)
    assert "receipt" not in json.dumps(output)


def test_queue_error_is_sanitized_and_health_saved() -> None:
    queue = FakeQueue([])
    queue.fail_receive = True
    with DeliveryStore() as store:
        worker = DeliveryWorker(
            store=store,
            client=queue,
            queue_url="https://sqs.example/queue",
            grant_id="grant-1",
            emit=lambda _: None,
        )
        with pytest.raises(RuntimeError, match=r"^delivery queue polling failed$"):
            worker.poll_once()
        assert store.health()["worker"]["error_code"] == "queue_error"


def test_empty_poll_records_healthy_heartbeat() -> None:
    with DeliveryStore() as store:
        worker = DeliveryWorker(
            store=store,
            client=FakeQueue([]),
            queue_url="https://sqs.example/queue",
            grant_id="grant-1",
            emit=lambda _: None,
        )
        assert worker.poll_once()["processed"] == 0
        assert store.health()["worker"]["last_success_at"] is not None
