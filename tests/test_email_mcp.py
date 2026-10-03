from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import types
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


class FakeMCP:
    def __init__(self, name: str) -> None:
        self.name = name

    def tool(self) -> Callable[[Callable[..., str]], Callable[..., str]]:
        return lambda function: function

    def run(self) -> None:
        raise AssertionError("server should not run during import")


def _load(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    mcp_module = types.ModuleType("mcp")
    server_module = types.ModuleType("mcp.server")
    fastmcp_module = types.ModuleType("mcp.server.fastmcp")
    fastmcp_module.FastMCP = FakeMCP  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "mcp", mcp_module)
    monkeypatch.setitem(sys.modules, "mcp.server", server_module)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fastmcp_module)
    path = Path(__file__).parents[1] / "deploy/macos/hermes-email-mcp.py"
    spec = importlib.util.spec_from_file_location("email_mcp_under_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_mcp_sends_exact_json_through_fixed_wrapper_without_provider_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load(monkeypatch)
    wrapper = tmp_path / "run-email-send.sh"
    wrapper.write_text("#!/bin/sh\nexit 1\n")
    wrapper.chmod(0o700)
    monkeypatch.setenv("EMAIL_BRIDGE_SEND_WRAPPER", str(wrapper))
    monkeypatch.setenv("EMAIL_BRIDGE_ENV_FILE", str(tmp_path / "config.env"))
    monkeypatch.setenv("NYLAS_API_KEY", "must-not-reach-child")
    calls: list[dict[str, Any]] = []

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append({"args": args, "kwargs": kwargs})
        return subprocess.CompletedProcess(
            args[0],
            0,
            stdout='{"duplicate":false,"provider_message_id":"sent-1"}\n',
            stderr="",
        )

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    response = module.email_send(
        "operation-1",
        "recipient@example.test",
        "Subject",
        text="Open fmp://record/123",
    )
    assert json.loads(response) == {"duplicate": False, "provider_message_id": "sent-1"}
    request = json.loads(calls[0]["kwargs"]["input"])
    assert request["text"] == "Open fmp://record/123"
    assert calls[0]["args"] == ([str(wrapper)],)
    child_env = calls[0]["kwargs"]["env"]
    assert set(child_env) == {"EMAIL_BRIDGE_ENV_FILE", "HOME", "LANG", "PATH"}
    assert "must-not-reach-child" not in json.dumps(child_env)


def test_mcp_rejects_unsafe_wrapper_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load(monkeypatch)
    wrapper = tmp_path / "run-email-send.sh"
    wrapper.write_text("#!/bin/sh\nexit 1\n")
    wrapper.chmod(0o722)
    monkeypatch.setenv("EMAIL_BRIDGE_SEND_WRAPPER", str(wrapper))
    with pytest.raises(RuntimeError, match="unsafe metadata"):
        module._send_wrapper()

    wrapper.chmod(0o700)
    link = tmp_path / "linked" / "run-email-send.sh"
    link.parent.mkdir()
    os.symlink(wrapper, link)
    monkeypatch.setenv("EMAIL_BRIDGE_SEND_WRAPPER", str(link))
    with pytest.raises(RuntimeError, match="approved wrapper"):
        module._send_wrapper()
