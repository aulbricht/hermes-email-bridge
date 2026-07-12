import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from hermes_email_bridge.cli import _run_poll_loop, main
from hermes_email_bridge.models import NormalizedEmail, PollSummary, SenderAuthentication
from hermes_email_bridge.providers.base import RetryableProviderError
from hermes_email_bridge.service import BridgeService
from hermes_email_bridge.store import MappingStore


def test_mappings_masks_marker_and_rotation_reveals_new_value_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "bridge.db"
    with MappingStore(path) as store:
        mapping = store.add_mapping(
            provider="agentmail",
            hermes_session="session-1",
            participant_email="person@example.com",
        )
    monkeypatch.setenv("EMAIL_BRIDGE_DB_PATH", str(path))

    assert main(["mappings"]) == 0
    listed = capsys.readouterr().out
    assert mapping.bridge_marker not in listed
    assert json.loads(listed)[0]["bridge_marker"].startswith("v1:****")

    assert main(["mappings", "rotate", str(mapping.id), "--ttl-days", "7"]) == 0
    rotated = json.loads(capsys.readouterr().out)
    assert rotated["bridge_marker"].startswith("v1:")
    assert len(rotated["bridge_marker"]) > 20

    assert main(["mappings"]) == 0
    relisted = capsys.readouterr().out
    assert rotated["bridge_marker"] not in relisted


def test_purge_raw_cli_preserves_idempotency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "bridge.db"
    message = NormalizedEmail(
        provider="agentmail",
        provider_message_id="message-1",
        from_email="person@example.com",
        to_email="bridge@example.com",
        subject="Subject",
        text_body="Body",
        received_at=datetime(2026, 7, 10, tzinfo=UTC),
        raw_payload={"secret": "sensitive body"},
        sender_authentication=SenderAuthentication.AUTHENTICATED,
    )
    with MappingStore(path) as store:
        store.mark_processed(message, "done", store_raw=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE processed_messages SET processed_at = ?",
            ((datetime.now(UTC) - timedelta(days=31)).isoformat(),),
        )
    monkeypatch.setenv("EMAIL_BRIDGE_DB_PATH", str(path))

    assert main(["purge-raw", "--older-than-days", "30"]) == 0
    assert json.loads(capsys.readouterr().out) == {"purged": 1}
    with MappingStore(path) as store:
        assert store.is_processed("agentmail", "message-1")


def test_allowlist_cli_add_list_remove(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("EMAIL_BRIDGE_DB_PATH", str(tmp_path / "bridge.db"))
    assert main(["allowlist", "add", "Person@Example.Test"]) == 0
    assert json.loads(capsys.readouterr().out)["address"] == "person@example.test"
    assert main(["allowlist", "list"]) == 0
    assert [item["address"] for item in json.loads(capsys.readouterr().out)] == [
        "person@example.test"
    ]
    assert main(["allowlist", "remove", "person@example.test"]) == 0
    assert json.loads(capsys.readouterr().out) == {"removed": True}


def test_init_db_start_now_seeds_both_agentmail_cursors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "bridge.db"
    monkeypatch.setenv("EMAIL_BRIDGE_DB_PATH", str(path))
    assert main(["init-db", "--start-now"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["seeded"] == ["agentmail", "agentmail:sent"]
    with MappingStore(path) as store:
        assert store.get_cursor("agentmail")
        assert store.get_cursor("agentmail:sent")


def test_continuous_poll_backoff_honors_retry_after_and_resets_after_success() -> None:
    class SequenceService:
        def __init__(self) -> None:
            self.results: list[PollSummary | Exception] = [
                RetryableProviderError("retry", retry_after=8),
                RetryableProviderError("retry"),
                PollSummary(0, 0, 0, 0),
                RetryableProviderError("retry"),
            ]

        def poll_once(self) -> PollSummary:
            result = self.results.pop(0)
            if isinstance(result, Exception):
                raise result
            return result

    delays: list[float] = []

    def stop_after_four(delay: float) -> None:
        delays.append(delay)
        if len(delays) == 4:
            raise KeyboardInterrupt

    service = cast(BridgeService, SequenceService())
    with pytest.raises(KeyboardInterrupt):
        _run_poll_loop(service, continuous=True, interval=5, sleep=stop_after_four)
    assert delays == [8, 10, 5, 5]


def test_continuous_poll_does_not_retry_nonretryable_failures() -> None:
    class BrokenService:
        def poll_once(self) -> PollSummary:
            raise ValueError("malformed response")

    with pytest.raises(ValueError, match="malformed"):
        _run_poll_loop(
            cast(BridgeService, BrokenService()),
            continuous=True,
            interval=5,
            sleep=lambda _delay: pytest.fail("unexpected retry"),
        )


def test_version_reports_project_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["--version"])
    assert stopped.value.code == 0
    assert capsys.readouterr().out.strip() == "0.3.0"
