from __future__ import annotations

import importlib.util
import os
import pwd
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
WRAPPER_PATH = ROOT / "deploy/macos/hermes-email-agent-wrapper.py"
PROBE_PATH = ROOT / "deploy/macos/verify-hermes-email-agent.py"
RUNTIME_PATH = ROOT / "deploy/macos/install-hermes-email-runtime.py"


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


def _load_runtime() -> Any:
    spec = importlib.util.spec_from_file_location("hermes_email_runtime_boundary", RUNTIME_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
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

    hermes = "/Library/Application Support/HermesEmailAgent/hermes-agent/runtime/venv/bin/hermes"
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


def _boundary_fixture(tmp_path: Path) -> tuple[Any, Any, Path, Path, Path]:
    probe = _load_probe()
    runtime = _load_runtime()
    candidates = tmp_path / "candidates"
    boundary = tmp_path / "boundary"
    candidates.mkdir(mode=0o755)
    boundary.mkdir(mode=0o755)
    candidate_wrapper = candidates / "hermes-email-agent-wrapper.py"
    candidate_wrapper.write_bytes(WRAPPER_PATH.read_bytes())
    candidate_template = candidates / "hermes-email-agent.sudoers"
    candidate_template.write_bytes((ROOT / "deploy/macos/hermes-email-agent.sudoers").read_bytes())
    wrapper = boundary / "hermes-email-agent"
    wrapper.write_bytes(candidate_wrapper.read_bytes())
    wrapper.chmod(0o755)
    sudoers = boundary / "hermes-email-agent.sudoers"
    user = pwd.getpwuid(os.getuid()).pw_name
    sudoers.write_text(candidate_template.read_text().replace("__BRIDGE_USER__", user))
    sudoers.chmod(0o440)
    return probe, runtime, candidates, wrapper, sudoers


def test_runtime_verifier_requires_exact_attested_wrapper_and_sudoers_bytes(
    tmp_path: Path,
) -> None:
    probe, runtime, candidates, wrapper, sudoers = _boundary_fixture(tmp_path)
    uid, gid = os.getuid(), os.getgid()
    evidence = probe.verify_fixed_boundary(
        runtime,
        uid=uid,
        gid=gid,
        wrapper=wrapper,
        sudoers=sudoers,
        candidate_directory=candidates,
    )
    assert evidence["bridge_user"] == pwd.getpwuid(uid).pw_name
    assert len(evidence["wrapper_sha256"]) == 64
    assert len(evidence["sudoers_sha256"]) == 64


@pytest.mark.parametrize(
    "mutation,error",
    [
        ("wrapper-byte", "wrapper bytes"),
        ("broader-policy", "policy shape"),
        ("stale-wrapper", "wrapper bytes"),
        ("wrong-user", "startup verifier user"),
    ],
)
def test_runtime_verifier_rejects_tampered_boundary_bytes(
    tmp_path: Path, mutation: str, error: str
) -> None:
    probe, runtime, candidates, wrapper, sudoers = _boundary_fixture(tmp_path)
    if mutation == "wrapper-byte":
        wrapper.write_bytes(wrapper.read_bytes() + b"\n")
    elif mutation == "broader-policy":
        sudoers.chmod(0o600)
        sudoers.write_text(
            sudoers.read_text().replace(
                "/usr/local/libexec/hermes-email-agent",
                "/usr/local/libexec/hermes-email-agent, /usr/bin/id",
            )
        )
        sudoers.chmod(0o440)
    elif mutation == "stale-wrapper":
        wrapper.write_text(wrapper.read_text().replace('"gpt-5.5"', '"gpt-5.4"'))
    else:
        sudoers.chmod(0o600)
        sudoers.write_text(
            (candidates / "hermes-email-agent.sudoers")
            .read_text()
            .replace("__BRIDGE_USER__", "wrong_bridge_user")
        )
        sudoers.chmod(0o440)
    with pytest.raises(ValueError, match=error):
        probe.verify_fixed_boundary(
            runtime,
            uid=os.getuid(),
            gid=os.getgid(),
            wrapper=wrapper,
            sudoers=sudoers,
            candidate_directory=candidates,
        )


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
