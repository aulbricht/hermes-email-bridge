"""Pull authenticated normalized delivery events from SQS; never resend mail."""

from __future__ import annotations

import argparse
import importlib
import json
import signal
import threading
from collections.abc import Callable
from typing import Any, Protocol

from .delivery import DeliveryEvent, DeliveryStore


class QueueClient(Protocol):
    def receive_message(self, **kwargs: Any) -> dict[str, Any]: ...
    def delete_message(self, **kwargs: Any) -> Any: ...
    def get_queue_attributes(self, **kwargs: Any) -> dict[str, Any]: ...


class DeliveryWorker:
    def __init__(
        self,
        *,
        store: DeliveryStore,
        client: QueueClient,
        queue_url: str,
        grant_id: str,
        emit: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if not queue_url.startswith("https://") or not grant_id:
            raise ValueError("HTTPS queue_url and grant_id are required")
        self.store, self.client, self.queue_url, self.grant_id = store, client, queue_url, grant_id
        self.emit = emit or (lambda value: print(json.dumps(value, sort_keys=True), flush=True))

    def poll_once(self) -> dict[str, int]:
        counts = {"processed": 0, "duplicates": 0, "quarantined": 0, "failed": 0}
        try:
            response = self.client.receive_message(
                QueueUrl=self.queue_url,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=20,
                VisibilityTimeout=60,
            )
        except Exception:
            self.store.worker_poll(error_code="queue_error")
            self.emit({"component": "email_delivery", "status": "queue_error"})
            raise RuntimeError("delivery queue polling failed") from None
        for message in response.get("Messages", []):
            try:
                body, receipt = message["Body"], message["ReceiptHandle"]
                if not isinstance(body, str) or len(body.encode()) > 16_384:
                    raise ValueError("invalid normalized event size")
                event = DeliveryEvent.from_dict(json.loads(body))
                if event.provider != "nylas" or event.grant_id != self.grant_id:
                    raise ValueError("event scope mismatch")
                result = self.store.apply_event(event)
                # Commit evidence before deleting. A crash or delete failure is
                # safe: redelivery finds the durable event identity.
                self.client.delete_message(QueueUrl=self.queue_url, ReceiptHandle=receipt)
                counts["processed"] += 1
                counts["duplicates"] += int(result.duplicate)
                counts["quarantined"] += int(result.disposition == "quarantined")
            except Exception:
                # Poison messages stay on the queue until SQS redrives to DLQ.
                # Neither body, receipt, exception text nor identifiers are logged.
                counts["failed"] += 1
        self.store.worker_poll(
            processed=counts["processed"], error_code="event_error" if counts["failed"] else None
        )
        self.emit({"component": "email_delivery", "status": "poll_complete", **counts})
        return counts

    def health(self) -> dict[str, Any]:
        value = self.store.health()
        try:
            attributes = self.client.get_queue_attributes(
                QueueUrl=self.queue_url,
                AttributeNames=[
                    "ApproximateNumberOfMessages",
                    "ApproximateNumberOfMessagesNotVisible",
                    "ApproximateNumberOfMessagesDelayed",
                ],
            )
            value["queue"] = {
                key: int(count) for key, count in attributes.get("Attributes", {}).items()
            }
        except Exception:
            value["queue"] = {"status": "unavailable"}
        return value

    def run(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                self.poll_once()
            except RuntimeError:
                stop.wait(5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-path", required=True)
    parser.add_argument("--queue-url", required=True)
    parser.add_argument("--grant-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--health", action="store_true")
    args = parser.parse_args(argv)
    try:
        boto3 = importlib.import_module("boto3")
    except ImportError:
        parser.error("delivery worker requires the aws optional dependency")
    with DeliveryStore(args.db_path) as store:
        worker = DeliveryWorker(
            store=store,
            client=boto3.client("sqs", region_name=args.region),
            queue_url=args.queue_url,
            grant_id=args.grant_id,
        )
        if args.health:
            print(json.dumps(worker.health(), sort_keys=True))
        elif args.once:
            return int(worker.poll_once()["failed"] > 0)
        else:
            stop = threading.Event()
            for signum in (signal.SIGINT, signal.SIGTERM):
                signal.signal(signum, lambda _signal, _frame: stop.set())
            worker.run(stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
