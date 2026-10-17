from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.request import Request

import pytest

from hermes_email_bridge.atlas_import_handoff import AtlasImportHandoff
from hermes_email_bridge.config import ConfigError, Settings
from hermes_email_bridge.models import Attachment, NormalizedEmail, SenderAuthentication


def _message(*, attachment: bool = True) -> NormalizedEmail:
    return NormalizedEmail(
        provider="nylas", provider_message_id="message-1", thread_id="thread-1",
        from_email="allen@example.invalid", to_email="agent@example.invalid",
        subject="Import", text_body="Please import", received_at=datetime.now(UTC),
        sender_authentication=SenderAuthentication.AUTHENTICATED,
        attachments=(Attachment("attachment-1", "rent.csv", "text/csv", 20),)
        if attachment else (),
    )


def test_atlas_import_handoff_sends_only_bounded_authenticated_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("a" * 48)
    os.chmod(token_file, 0o600)
    handoff = AtlasImportHandoff(
        origin="https://atlas.example.invalid", token_file=token_file, grant_id="grant-1",
    )
    message = _message()
    assert handoff.wants(message, None)
    seen_requests: list[Request] = []
    seen_timeouts: list[float] = []

    class Response:
        status = 200

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps({
                "status": "accepted", "owner_user_id": "usr_1", "session_id": "chat_1",
                "upload_id": "del_1", "import_id": "imp_1", "reply_text": "Please review",
            }).encode()

    class Opener:
        def open(self, request: Request, timeout: float) -> Response:
            seen_requests.append(request)
            seen_timeouts.append(timeout)
            return Response()

    monkeypatch.setattr(
        "hermes_email_bridge.atlas_import_handoff.build_opener", lambda *_args: Opener(),
    )
    assert handoff.handle(
        message, None, lambda attachment, max_bytes: (
            b"Name,Suite\nTenant A,A1\n" if max_bytes == 25 * 1024 * 1024 else b""
        ), "operation-1",
    ) == "Please review"
    request = seen_requests[0]
    assert request.full_url == (
        "https://atlas.example.invalid/api/v1/internal/email-import-handoff"
    )
    assert request.get_header("X-atlas-email-import-token") == "a" * 48
    assert isinstance(request.data, bytes)
    body = json.loads(request.data)
    assert body["action"] == "import" and body["grant_id"] == "grant-1"
    assert body["attachment_ids"] == ["attachment-1"]
    assert body["text_body"] == "Please import"
    assert seen_timeouts == [3_660]


def test_atlas_import_handoff_waits_for_slow_completed_turn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("a" * 48)
    os.chmod(token_file, 0o600)
    handoff = AtlasImportHandoff(
        origin="https://atlas.example.invalid", token_file=token_file, grant_id="grant-1",
    )

    class Response:
        status = 200

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps({
                "status": "accepted", "owner_user_id": "usr_1", "session_id": "chat_1",
                "upload_id": "del_1", "import_id": "imp_1", "reply_text": "Completed",
            }).encode()

    class SlowOpener:
        def open(self, _request: object, timeout: float) -> Response:
            assert timeout > 3_600
            time.sleep(0.05)
            return Response()

    monkeypatch.setattr(
        "hermes_email_bridge.atlas_import_handoff.build_opener", lambda *_args: SlowOpener(),
    )
    result = handoff.handle(
        _message(), None, lambda *_args: b"Name,Suite\nTenant A,A1\n", "op-1",
    )
    assert result == "Completed"


def test_atlas_import_handoff_rejects_unsupported_or_unsafe_content(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("a" * 48)
    os.chmod(token_file, 0o644)
    handoff = AtlasImportHandoff(
        origin="https://atlas.example.invalid", token_file=token_file, grant_id="grant-1",
    )
    with pytest.raises(RuntimeError, match="unsafe"):
        handoff.handle(_message(), None, lambda *_args: b"csv", "operation-1")
    unsupported = _message()
    object.__setattr__(unsupported, "attachments", (Attachment("att", "report.docx"),))
    assert not handoff.wants(unsupported, None)


def test_atlas_import_configuration_requires_https_and_token_pair() -> None:
    with pytest.raises(ConfigError, match="configured together"):
        Settings.from_env({"EMAIL_BRIDGE_ATLAS_IMPORT_ORIGIN": "https://atlas.example.invalid"})
    with pytest.raises(ConfigError, match="must use HTTPS"):
        Settings.from_env({
            "EMAIL_BRIDGE_ATLAS_IMPORT_ORIGIN": "http://atlas.example.invalid",
            "EMAIL_BRIDGE_ATLAS_IMPORT_TOKEN_FILE": "/tmp/token",
        })
    with pytest.raises(ConfigError, match="must not include a path"):
        Settings.from_env({
            "EMAIL_BRIDGE_ATLAS_IMPORT_ORIGIN": "https://atlas.example.invalid/other",
            "EMAIL_BRIDGE_ATLAS_IMPORT_TOKEN_FILE": "/tmp/token",
        })


def test_email_text_is_bounded_and_control_characters_removed() -> None:
    from hermes_email_bridge.atlas_import_handoff import _user_text

    assert _user_text("  Change suite\x00 to A2\r\n") == "Change suite to A2"
    assert len(_user_text("x" * 10_000)) == 8_000
