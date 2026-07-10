import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from hermes_email_bridge.cli import main
from hermes_email_bridge.models import NormalizedEmail, SenderAuthentication
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
