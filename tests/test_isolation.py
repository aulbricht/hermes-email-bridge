from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
WRAPPER_PATH = ROOT / "deploy/macos/hermes-email-agent-wrapper.py"
PROBE_PATH = ROOT / "deploy/macos/verify-hermes-email-agent.py"


def _load_wrapper() -> Any:
    spec = importlib.util.spec_from_file_location("hermes_email_agent_wrapper", WRAPPER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_probe() -> Any:
    spec = importlib.util.spec_from_file_location("hermes_email_agent_probe", PROBE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_wrapper_accepts_only_runner_argument_shapes() -> None:
    wrapper = _load_wrapper()
    build = wrapper.build_invocation
    cwd, argv, env = build(["--query", "email prompt"])
    assert cwd == "/var/db/hermes-email-agent/workspace"
    assert argv[-2:] == ("--query", "email prompt")
    assert "--resume" not in argv
    assert env == {
        "HOME": "/var/db/hermes-email-agent",
        "HERMES_HOME": "/var/db/hermes-email-agent",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "en_US.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }

    _cwd, resumed, _env = build(["--resume", "20260711_120000_ab12-CD34", "--query", "follow-up"])
    assert resumed[-4:] == (
        "--resume",
        "20260711_120000_ab12-CD34",
        "--query",
        "follow-up",
    )


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["--query"],
        ["--query", ""],
        ["--query", "--yolo"],
        ["--unknown", "value"],
        ["--query", "one", "--query", "two"],
        ["--resume", "valid", "--resume", "other", "--query", "prompt"],
        ["--resume", "../session", "--query", "prompt"],
        ["--resume", "session.with.dot", "--query", "prompt"],
        ["--resume", "-starts-with-dash", "--query", "prompt"],
        ["--resume", "a" * 129, "--query", "prompt"],
    ],
)
def test_wrapper_rejects_unknown_repeated_and_malformed_arguments(arguments: list[str]) -> None:
    with pytest.raises(ValueError):
        _load_wrapper().build_invocation(arguments)


def test_wrapper_executes_only_fixed_cwd_argv_and_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrapper = _load_wrapper()
    monkeypatch.setenv("ARBITRARY_PARENT_SENTINEL", "must-not-cross")
    calls: dict[str, Any] = {}

    def fake_chdir(path: str) -> None:
        calls["cwd"] = path

    def fake_execve(path: str, argv: list[str], env: dict[str, str]) -> None:
        calls.update(path=path, argv=argv, env=env)

    wrapper_os = wrapper.os
    monkeypatch.setattr(wrapper_os, "chdir", fake_chdir)
    monkeypatch.setattr(wrapper_os, "execve", fake_execve)
    assert wrapper.main(["--query", "fixed prompt"]) == 70

    hermes = "/Library/Application Support/HermesEmailAgent/hermes-agent/venv/bin/hermes"
    assert calls["cwd"] == "/var/db/hermes-email-agent/workspace"
    assert calls["path"] == hermes
    assert calls["argv"] == [
        hermes,
        "chat",
        "--quiet",
        "--source",
        "tool",
        "--safe-mode",
        "--toolsets",
        "context_engine",
        "--provider",
        "openai-codex",
        "--model",
        "gpt-5.5",
        "--max-turns",
        "1",
        "--query",
        "fixed prompt",
    ]
    assert calls["env"] == wrapper._ENV
    assert "ARBITRARY_PARENT_SENTINEL" not in calls["env"]


def test_wrapper_executable_rejects_unknown_shape_without_echoing_input() -> None:
    secret_argument = "unknown-sensitive-value"
    result = subprocess.run(
        [sys.executable, str(WRAPPER_PATH), "--unknown", secret_argument],
        env={"PATH": os.environ.get("PATH", os.defpath)},
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 64
    assert secret_argument not in result.stderr


def test_wrapper_contract_new_and_resume_have_zero_schemas_and_clean_streams(
    tmp_path: Path,
) -> None:
    wrapper = _load_wrapper()
    stub = tmp_path / "pinned-hermes-stub.py"
    stub.write_text(
        """import sys

PINNED_COMMIT = "4281151ae859241351ba14d8c7682dc67ff4c126"
TOOL_DEFINITIONS = {"context_engine": []}
def get_tool_definitions(toolset, *, quiet_mode):
    assert quiet_mode is True
    return TOOL_DEFINITIONS[toolset]
expected = [
    "chat", "--quiet", "--source", "tool", "--safe-mode",
    "--toolsets", "context_engine", "--provider", "openai-codex",
    "--model", "gpt-5.5", "--max-turns", "1",
]
arguments = sys.argv[1:]
assert arguments[:len(expected)] == expected
tail = arguments[len(expected):]
if tail[:1] == ["--resume"]:
    session = tail[1]
    tail = tail[2:]
else:
    session = "new-session"
assert tail[0] == "--query" and len(tail) == 2
assert get_tool_definitions("context_engine", quiet_mode=True) == []
print("answer only")
print(f"session_id: {session}", file=sys.stderr)
"""
    )

    def run(arguments: list[str]) -> subprocess.CompletedProcess[str]:
        _cwd, fixed_argv, env = wrapper.build_invocation(arguments)
        assert fixed_argv[fixed_argv.index("--toolsets") + 1] == "context_engine"
        assert not {"none", "no_mcp", "", "default"} & set(fixed_argv)
        return subprocess.run(
            [sys.executable, str(stub), *fixed_argv[1:]],
            capture_output=True,
            check=False,
            env=env,
            text=True,
        )

    fresh = run(["--query", "new email"])
    assert fresh.returncode == 0
    assert fresh.stdout == "answer only\n"
    assert fresh.stderr == "session_id: new-session\n"
    assert "warning" not in (fresh.stdout + fresh.stderr).lower()

    resumed = run(["--resume", "session_123", "--query", "reply email"])
    assert resumed.returncode == 0
    assert resumed.stdout == "answer only\n"
    assert resumed.stderr == "session_id: session_123\n"
    assert "warning" not in (resumed.stdout + resumed.stderr).lower()


def test_runtime_probe_validates_wrapper_and_live_new_resume_streams() -> None:
    probe = _load_probe()
    probe.verify_wrapper_shapes(WRAPPER_PATH)
    results = iter(
        (
            subprocess.CompletedProcess(
                [], 0, stdout="EMAIL_BRIDGE_PROBE_OK\n", stderr="session_id: live_session\n"
            ),
            subprocess.CompletedProcess(
                [], 0, stdout="EMAIL_BRIDGE_RESUME_OK\n", stderr="session_id: live_session\n"
            ),
        )
    )
    calls: list[list[str]] = []

    def runner(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return next(results)

    probe.verify_live(runner=runner)
    assert calls[0][-2] == "--query"
    assert calls[1][-4:-2] == ["--resume", "live_session"]


@pytest.mark.parametrize(
    "arguments",
    [
        ["--source", "/tmp/source"],
        ["--python", "/tmp/venv/bin/python"],
        ["--wrapper", "/tmp/wrapper"],
    ],
)
def test_runtime_verifier_cli_rejects_arbitrary_runtime_paths(arguments: list[str]) -> None:
    with pytest.raises(SystemExit):
        _load_probe().main(arguments)
