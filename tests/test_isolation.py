from __future__ import annotations

import grp
import hashlib
import importlib.util
import json
import os
import pwd
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from hermes_email_bridge.models import NormalizedEmail, SenderAuthentication
from hermes_email_bridge.providers.fake import FakeProvider
from hermes_email_bridge.runner import SubprocessHermesRunner
from hermes_email_bridge.service import BridgeService
from hermes_email_bridge.store import MappingStore

ROOT = Path(__file__).parents[1]
WRAPPER_PATH = ROOT / "deploy/macos/hermes-email-agent-wrapper.py"
ADAPTER_PATH = ROOT / "deploy/macos/hermes-email-agent-adapter.py"
PROBE_PATH = ROOT / "deploy/macos/verify-hermes-email-agent.py"
BOUNDARY_HELPER_PATH = ROOT / "deploy/macos/hermes-email-boundary-verify.py"
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


def _load_boundary_helper() -> Any:
    spec = importlib.util.spec_from_file_location(
        "hermes_email_boundary_helper", BOUNDARY_HELPER_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _synthetic_account_evidence(_bridge_user: str) -> dict[str, object]:
    return {
        "bridge_uid": 501,
        "build_uid": 503,
        "inference_uid": 502,
        "inference_user": "_hermesmail",
    }


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
    assert argv[:4] == (
        "/Library/Application Support/HermesEmailAgent/hermes-agent/runtime/venv/bin/python",
        "-I",
        "-B",
        "/Library/Application Support/HermesEmailAgent/hermes-agent/runtime/"
        "hermes-email-agent-adapter.py",
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

    python = "/Library/Application Support/HermesEmailAgent/hermes-agent/runtime/venv/bin/python"
    assert calls["cwd"] == "/var/db/hermes-email-agent/workspace"
    assert calls["path"] == python
    assert calls["argv"] == [
        python,
        "-I",
        "-B",
        "/Library/Application Support/HermesEmailAgent/hermes-agent/runtime/"
        "hermes-email-agent-adapter.py",
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


def test_programmatic_adapter_suppresses_all_process_output_and_emits_only_protocol(
    tmp_path: Path,
) -> None:
    fake = tmp_path / "cli.py"
    fake.write_text(
        """import os, sys
from pathlib import Path
print("IMPORT TRANSCRIPT")
os.write(2, b"IMPORT STDERR\\n")
class Agent:
    def __init__(self, session):
        self.session_id = session
        self.model = os.environ.get("FAKE_EXPECTED_MODEL", "gpt-5.5")
        self.provider = os.environ.get("FAKE_EXPECTED_PROVIDER", "openai-codex")
        self.tools = []
        self._context_engine_tool_names = set()
        self.context_compressor = self
    def get_tool_schemas(self):
        return ["unexpected"] if os.environ.get("FAKE_RESULT_MODE") == "context-tools" else []
    def run_conversation(self, **kwargs):
        incident = Path(os.environ["INCIDENT_FIXTURE"]).read_text().replace("\u241b", "\x1b")
        os.write(1, incident.encode())
        os.write(2, b"TIMEOUT AND SECRET-CANARY\\n")
        result = {"final_response":'{"action":"reply","reply":"Short intended reply."}',
                  "session_id":self.session_id,
                  "completed":True,"failed":False,"partial":False,"interrupted":False,
                  "turn_exit_reason":"text_response(finish_reason=stop)",
                  "response_transformed":False,"response_previewed":False,
                  "model":self.model,"provider":self.provider}
        mode = os.environ.get("FAKE_RESULT_MODE")
        if mode in {"failed", "partial", "interrupted"}: result[mode] = True
        if mode == "incomplete": result["completed"] = False
        if mode == "cleanup": result["cleanup_errors"] = ["SECRET-CANARY"]
        if mode == "wrong-session": result["session_id"] = "different_session"
        if mode == "agent-session": self.session_id = "different_session"
        if mode in {"partial_stream_recovery", "fallback_prior_turn_content"}:
            result["turn_exit_reason"] = mode
        if mode == "missing-exit": result.pop("turn_exit_reason")
        if mode == "unknown-exit": result["turn_exit_reason"] = "unknown"
        if mode == "length-exit":
            result["turn_exit_reason"] = "text_response(finish_reason=length)"
        if mode == "content-filter-exit":
            result["turn_exit_reason"] = "text_response(finish_reason=content_filter)"
        if mode == "budget-exit": result["turn_exit_reason"] = "budget_exhausted"
        if mode == "timeout-exit": result["turn_exit_reason"] = "max_iterations_reached(1/1)"
        if mode == "transformed": result["response_transformed"] = True
        if mode == "previewed": result["response_previewed"] = True
        if mode == "pending-steer": result["pending_steer"] = "benign-looking follow-up"
        if mode == "result-model": result["model"] = "different-model"
        if mode == "agent-model": self.model = "different-model"
        if mode == "result-provider": result["provider"] = "different-provider"
        if mode == "agent-provider": self.provider = "different-provider"
        if mode == "decision-text": result["final_response"] = "Short intended reply."
        if mode == "decision-extra":
            result["final_response"] = '{"action":"reply","reply":"ok","extra":true}'
        if mode == "decision-duplicate":
            result["final_response"] = (
                '{"action":"reply","action":"approval_required","reply":"ok"}'
            )
        if mode == "decision-action":
            result["final_response"] = '{"action":"run_tools","reply":"ok"}'
        if mode == "agent-tools": self.tools = ["unexpected"]
        if mode == "context-tool-names": self._context_engine_tool_names = {"unexpected"}
        return result
class HermesCLI:
    def __init__(self, **kwargs):
        model = os.environ.get("FAKE_EXPECTED_MODEL", "gpt-5.5")
        provider = os.environ.get("FAKE_EXPECTED_PROVIDER", "openai-codex")
        assert kwargs == {"model":model,"toolsets":["context_engine"],
                          "provider":provider,"max_turns":1,
                          "resume":kwargs.get("resume"),"ignore_rules":True}
        self.session_id = kwargs.get("resume") or "fresh_session"
        self.agent = Agent(self.session_id)
        self.enabled_toolsets = ["context_engine"]
        self.conversation_history = []
    def _claim_active_session(self, surface, stderr=False):
        print("CLAIM")
        return surface == "cli" and stderr is True
    def _ensure_runtime_credentials(self): return True
    def _resolve_turn_agent_config(self, query):
        return {"model":self.agent.model,"runtime":{},"request_overrides":None}
    def _init_agent(self, **kwargs): return True
def _finalize_single_query(cli):
    print("FINALIZE")
    os.write(2, b"CLEANUP STDERR\\n")
    if os.environ.get("FAKE_RESULT_MODE") == "finalize": raise RuntimeError("SECRET-CANARY")
def get_tool_definitions(**kwargs):
    assert kwargs == {"enabled_toolsets":["context_engine"],"quiet_mode":True}
    return ["unexpected"] if os.environ.get("FAKE_RESULT_MODE") == "model-tools" else []
"""
    )
    bootstrap = (
        "import importlib.metadata,runpy,sys;"
        "importlib.metadata.version=lambda name:'0.18.2';"
        f"sys.path.insert(0,{str(tmp_path)!r});"
        f"m=runpy.run_path({str(ADAPTER_PATH)!r});"
        "raise SystemExit(m['main'](sys.argv[1:]))"
    )

    def run(arguments: list[str], mode: str | None = None) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["INCIDENT_FIXTURE"] = str(
            ROOT / "tests/fixtures/incident_terminal_transcript.txt"
        )
        if mode is not None:
            environment["FAKE_RESULT_MODE"] = mode
        if arguments[:2] == ["--runtime", "openrouter"]:
            environment["FAKE_EXPECTED_MODEL"] = "z-ai/glm-5.2"
            environment["FAKE_EXPECTED_PROVIDER"] = "openrouter"
        return subprocess.run(
            [sys.executable, "-c", bootstrap, *arguments],
            capture_output=True,
            check=False,
            env=environment,
            text=True,
        )

    fresh = run(["--query", "new email"])
    assert fresh.returncode == 0 and fresh.stderr == ""
    assert json.loads(fresh.stdout) == {
        "action": "reply",
        "protocol": "hermes-email-bridge/2",
        "reply": "Short intended reply.",
        "session_id": "fresh_session",
    }
    assert fresh.stdout == (
        '{"action":"reply","protocol":"hermes-email-bridge/2",'
        '"reply":"Short intended reply.",'
        '"session_id":"fresh_session"}\n'
    )

    resumed = run(["--resume", "session_123", "--query", "reply email"])
    assert resumed.returncode == 0 and resumed.stderr == ""
    assert json.loads(resumed.stdout)["session_id"] == "session_123"

    openrouter = run(["--runtime", "openrouter", "--query", "new email"])
    assert openrouter.returncode == 0 and openrouter.stderr == ""
    assert json.loads(openrouter.stdout)["reply"] == "Short intended reply."

    openrouter_resumed = run(
        ["--runtime", "openrouter", "--resume", "session_456", "--query", "reply email"]
    )
    assert openrouter_resumed.returncode == 0 and openrouter_resumed.stderr == ""
    assert json.loads(openrouter_resumed.stdout)["session_id"] == "session_456"

    openrouter_mismatch = run(
        ["--runtime", "openrouter", "--query", "new email"], "result-provider"
    )
    assert (
        openrouter_mismatch.returncode == 1
        and openrouter_mismatch.stdout == openrouter_mismatch.stderr == ""
    )

    for invalid in (
        ["--runtime", "unknown", "--query", "new email"],
        ["--runtime", "openrouter", "--runtime", "openrouter", "--query", "new email"],
    ):
        rejected = run(invalid)
        assert rejected.returncode == 1 and rejected.stdout == rejected.stderr == ""

    for mode in (
        "failed",
        "partial",
        "interrupted",
        "incomplete",
        "cleanup",
        "wrong-session",
        "agent-session",
        "finalize",
        "partial_stream_recovery",
        "fallback_prior_turn_content",
        "missing-exit",
        "unknown-exit",
        "length-exit",
        "content-filter-exit",
        "budget-exit",
        "timeout-exit",
        "transformed",
        "previewed",
        "pending-steer",
        "result-model",
        "agent-model",
        "result-provider",
        "agent-provider",
        "decision-text",
        "decision-extra",
        "decision-duplicate",
        "decision-action",
        "context-tools",
        "model-tools",
        "agent-tools",
        "context-tool-names",
    ):
        rejected = run(["--query", "new email"], mode)
        assert rejected.returncode == 1
        assert rejected.stdout == rejected.stderr == ""

    incident_fixture = str(ROOT / "tests/fixtures/incident_terminal_transcript.txt")
    e2e_bootstrap = (
        "import importlib.metadata,os,runpy,sys;"
        "importlib.metadata.version=lambda name:'0.18.2';"
        f"os.environ['INCIDENT_FIXTURE']={incident_fixture!r};"
        "os.environ['FAKE_RESULT_MODE']='partial_stream_recovery';"
        f"sys.path.insert(0,{str(tmp_path)!r});"
        f"m=runpy.run_path({str(ADAPTER_PATH)!r});"
        "raise SystemExit(m['main'](sys.argv[1:]))"
    )
    command = shlex.join([sys.executable, "-c", e2e_bootstrap])
    message = NormalizedEmail(
        provider="fake",
        provider_message_id="provenance-failure",
        from_email="sender@example.invalid",
        to_email="bridge@example.invalid",
        subject="Provenance failure",
        text_body="Do not deliver fallback content",
        received_at=datetime.now(UTC),
        sender_authentication=SenderAuthentication.AUTHENTICATED,
    )
    provider = FakeProvider([message])
    with MappingStore(":memory:") as store:
        store.add_allowed_address("fake", message.from_email)
        service = BridgeService(
            provider=provider,
            store=store,
            runner=SubprocessHermesRunner(command),
            send_replies=True,
            dry_run=False,
        )
        assert service.handle(message) == "processed"
        assert provider.replies == []
        assert store.list_mappings() == []


def test_runtime_probe_validates_wrapper_and_live_new_resume_streams() -> None:
    probe = _load_probe()
    probe.verify_wrapper_shapes(WRAPPER_PATH)
    probe.verify_adapter_shape(ADAPTER_PATH)
    results = iter(
        (
            subprocess.CompletedProcess(
                [],
                0,
                stdout=(
                    '{"action":"reply","protocol":"hermes-email-bridge/2",'
                    '"reply":"EMAIL_BRIDGE_PROBE_OK",'
                    '"session_id":"live_session"}\n'
                ),
                stderr="",
            ),
            subprocess.CompletedProcess(
                [],
                0,
                stdout=(
                    '{"action":"reply","protocol":"hermes-email-bridge/2",'
                    '"reply":"EMAIL_BRIDGE_RESUME_OK",'
                    '"session_id":"rotated_session"}\n'
                ),
                stderr="",
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


def _boundary_fixture(tmp_path: Path) -> tuple[Any, Any, Path, Path, Path, Path, Any]:
    probe = _load_probe()
    runtime = _load_runtime()
    runtime.reject_acls = lambda _paths: None
    candidates = tmp_path / "candidates"
    boundary = tmp_path / "boundary"
    candidates.mkdir(mode=0o755)
    boundary.mkdir(mode=0o755)
    candidate_wrapper = candidates / "hermes-email-agent-wrapper.py"
    candidate_wrapper.write_bytes(WRAPPER_PATH.read_bytes())
    candidate_adapter = candidates / "hermes-email-agent-adapter.py"
    candidate_adapter.write_bytes(ADAPTER_PATH.read_bytes())
    candidate_template = candidates / "hermes-email-agent.sudoers"
    candidate_template.write_bytes((ROOT / "deploy/macos/hermes-email-agent.sudoers").read_bytes())
    candidate_helper = candidates / "hermes-email-boundary-verify.py"
    candidate_helper.write_bytes(BOUNDARY_HELPER_PATH.read_bytes())
    wrapper = boundary / "hermes-email-agent"
    wrapper.write_bytes(candidate_wrapper.read_bytes())
    wrapper.chmod(0o755)
    helper = boundary / "hermes-email-boundary-verify"
    helper.write_bytes(candidate_helper.read_bytes())
    helper.chmod(0o755)
    sudoers = boundary / "hermes-email-agent.sudoers"
    user = pwd.getpwuid(os.getuid()).pw_name
    sudoers.write_text(candidate_template.read_text().replace("__BRIDGE_USER__", user))
    sudoers.chmod(0o440)

    def runner(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        expected = (
            [str(helper)]
            if os.geteuid() == 0
            else ["/usr/bin/sudo", "-n", "-H", "-u", "root", str(helper)]
        )
        assert argv == expected
        policy = sudoers.read_text()
        match = re.match(r"Defaults:([A-Za-z_][A-Za-z0-9_-]{0,31}) ", policy)
        configured_user = "" if match is None else match.group(1)
        rendered = candidate_template.read_text().replace("__BRIDGE_USER__", configured_user)
        if policy != rendered:
            return subprocess.CompletedProcess(argv, 1, "", "boundary failure")
        evidence = {
            "accounts": _synthetic_account_evidence(configured_user),
            "bridge_user": configured_user,
            "sudoers_sha256": hashlib.sha256(rendered.encode()).hexdigest(),
            "wrapper_sha256": runtime.WRAPPER_SHA256,
        }
        return subprocess.CompletedProcess(
            argv, 0, json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n", ""
        )

    return probe, runtime, candidates, wrapper, helper, sudoers, runner


def test_runtime_verifier_requires_exact_attested_wrapper_and_sudoers_bytes(
    tmp_path: Path,
) -> None:
    probe, runtime, candidates, wrapper, helper, _sudoers, runner = _boundary_fixture(tmp_path)
    uid, gid = os.getuid(), os.getgid()
    evidence = probe.verify_fixed_boundary(
        runtime,
        uid=uid,
        gid=gid,
        wrapper=wrapper,
        helper=helper,
        candidate_directory=candidates,
        runner=runner,
        account_validator=_synthetic_account_evidence,
    )
    assert evidence["bridge_user"] == pwd.getpwuid(uid).pw_name
    assert len(evidence["wrapper_sha256"]) == 64
    assert len(evidence["sudoers_sha256"]) == 64


def test_runtime_verifier_rejects_mismatched_account_evidence(tmp_path: Path) -> None:
    probe, runtime, candidates, wrapper, helper, _sudoers, runner = _boundary_fixture(tmp_path)

    def tampered(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        result = runner(argv, **kwargs)
        evidence = json.loads(result.stdout)
        evidence["accounts"]["inference_uid"] = 999
        return subprocess.CompletedProcess(
            argv, 0, json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n", ""
        )

    with pytest.raises(ValueError, match="does not match"):
        probe.verify_fixed_boundary(
            runtime,
            uid=os.getuid(),
            gid=os.getgid(),
            wrapper=wrapper,
            helper=helper,
            candidate_directory=candidates,
            runner=tampered,
            account_validator=_synthetic_account_evidence,
        )


@pytest.mark.parametrize(
    "mutation,error",
    [
        ("wrapper-byte", "wrapper bytes"),
        ("broader-policy", "privileged boundary attestation failed"),
        ("stale-wrapper", "wrapper bytes"),
        ("adapter-byte", "adapter candidate"),
        ("helper-byte", "helper bytes"),
        ("wrong-user", "startup verifier user"),
    ],
)
def test_runtime_verifier_rejects_tampered_boundary_bytes(
    tmp_path: Path, mutation: str, error: str
) -> None:
    probe, runtime, candidates, wrapper, helper, sudoers, runner = _boundary_fixture(tmp_path)
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
        wrapper.write_text(wrapper.read_text().replace('"-I"', '"-E"'))
    elif mutation == "adapter-byte":
        adapter = candidates / "hermes-email-agent-adapter.py"
        adapter.write_bytes(adapter.read_bytes() + b"\n")
    elif mutation == "helper-byte":
        helper.write_bytes(helper.read_bytes() + b"\n")
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
            helper=helper,
            candidate_directory=candidates,
            runner=runner,
            account_validator=_synthetic_account_evidence,
        )


def _mac_account_inputs(helper: Any, failure: str | None = None) -> dict[str, Any]:
    def user(name: str, uid: int, gid: int, home: str, shell: str) -> pwd.struct_passwd:
        return pwd.struct_passwd((name, "*", uid, gid, "", home, shell))

    bridge = user("bridge_user", 501, 601, "/Users/bridge_user", "/bin/zsh")
    inference = user("_hermesmail", 502, 602, "/var/db/hermes-email-agent", "/usr/bin/false")
    builder = user("_hermesbuild", 503, 603, "/var/empty", "/usr/bin/false")
    if failure == "same_uid":
        inference = user(
            "_hermesmail", bridge.pw_uid, 602, "/var/db/hermes-email-agent", "/usr/bin/false"
        )
    elif failure == "wrong_home":
        inference = user("_hermesmail", 502, 602, "/tmp", "/usr/bin/false")
    elif failure == "wrong_shell":
        inference = user("_hermesmail", 502, 602, "/var/db/hermes-email-agent", "/bin/zsh")
    elif failure == "wrong_group":
        inference = user("_hermesmail", 502, 604, "/var/db/hermes-email-agent", "/usr/bin/false")
    elif failure == "admin":
        inference = user("_hermesmail", 502, 80, "/var/db/hermes-email-agent", "/usr/bin/false")
    elif failure == "staff":
        inference = user("_hermesmail", 502, 20, "/var/db/hermes-email-agent", "/usr/bin/false")
    accounts = {
        "bridge_user": bridge,
        "_hermesmail": inference,
        "_hermesbuild": builder,
    }
    group_items = [
        helper.grp.struct_group(("admin", "*", 80, [])),
        helper.grp.struct_group(("staff", "*", 20, [])),
        helper.grp.struct_group(("bridge_user", "*", 601, [])),
        helper.grp.struct_group(("_hermesmail", "*", inference.pw_gid, [])),
        helper.grp.struct_group(("_hermesbuild", "*", 603, [])),
    ]
    if failure == "supplementary":
        group_items.append(helper.grp.struct_group(("extra", "*", 700, ["_hermesmail"])))
    elif failure == "shared_group_member":
        group_items[3] = helper.grp.struct_group(("_hermesmail", "*", 602, ["other_user"]))
    by_name = {group.gr_name: group for group in group_items}
    by_gid = {group.gr_gid: group for group in group_items}
    if failure == "wrong_group":
        by_gid[inference.pw_gid] = helper.grp.struct_group(("other", "*", 604, []))

    def runner(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if argv[0] == "/usr/bin/dscl":
            output = "IsHidden: 0\n" if failure == "not_hidden" else "IsHidden: 1\n"
        else:
            group_name = argv[-1]
            member = failure == group_name
            output = (
                "user is a member of the group\n"
                if member
                else "user is not a member of the group\n"
            )
        return subprocess.CompletedProcess(argv, 0, output, "")

    return {
        "user_lookup": accounts.__getitem__,
        "users": lambda: list(accounts.values()),
        "group_lookup": by_name.__getitem__,
        "gid_lookup": by_gid.__getitem__,
        "groups": lambda: group_items,
        "runner": runner,
    }


def test_macos_account_invariants_accept_only_valid_dedicated_identities() -> None:
    helper = _load_boundary_helper()
    evidence = helper.validate_accounts("bridge_user", **_mac_account_inputs(helper))
    assert evidence == _synthetic_account_evidence("bridge_user")
    for reserved in ("root", "_hermesmail", "_hermesbuild"):
        with pytest.raises(ValueError, match="name"):
            helper.validate_accounts(reserved, **_mac_account_inputs(helper))
    missing = _mac_account_inputs(helper)
    missing["user_lookup"] = {}.__getitem__
    with pytest.raises(ValueError, match="missing"):
        helper.validate_accounts("bridge_user", **missing)


@pytest.mark.parametrize(
    "failure",
    [
        "same_uid",
        "wrong_home",
        "wrong_shell",
        "wrong_group",
        "admin",
        "staff",
        "supplementary",
        "shared_group_member",
        "not_hidden",
    ],
)
def test_macos_account_invariants_fail_closed(failure: str) -> None:
    helper = _load_boundary_helper()
    with pytest.raises(ValueError):
        helper.validate_accounts("bridge_user", **_mac_account_inputs(helper, failure))


def test_privileged_helper_rejects_args_and_broadened_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = _load_boundary_helper()
    template = (ROOT / "deploy/macos/hermes-email-agent.sudoers").read_text()
    policy = template.replace("__BRIDGE_USER__", "bridge_user").encode()
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    monkeypatch.setattr(helper, "_validate_directory", lambda _path: None)
    monkeypatch.setattr(
        helper,
        "_read_fixed",
        lambda path, _mode: WRAPPER_PATH.read_bytes() if path == helper.WRAPPER else policy,
    )
    monkeypatch.setattr(helper, "validate_accounts", _synthetic_account_evidence)
    assert helper.verify()["bridge_user"] == "bridge_user"
    with pytest.raises(ValueError, match="no arguments"):
        helper.main(["--alternate-path"])
    policy = policy.replace(b' ""\n', b' "", /usr/bin/id\n')
    with pytest.raises(ValueError, match="reviewed bytes"):
        helper.verify()


@pytest.mark.skipif(
    sys.platform != "darwin" or os.geteuid() != 0,
    reason="requires root and the installed macOS boundary",
)
def test_distinct_bridge_uid_cannot_read_sudoers_but_exact_helper_succeeds_and_tamper_fails(
    tmp_path: Path,
) -> None:
    probe = _load_probe()
    runtime = _load_runtime()
    if not (probe.WRAPPER.is_file() and probe.BOUNDARY_HELPER.is_file()):
        pytest.skip("fixed production boundary is not installed")
    direct = subprocess.run(
        [str(probe.BOUNDARY_HELPER)], capture_output=True, check=False, text=True
    )
    assert direct.returncode == 0 and direct.stderr == ""
    bridge_user = json.loads(direct.stdout)["bridge_user"]
    assert bridge_user not in {"root", "_hermesmail"}
    unreadable = subprocess.run(
        ["/usr/bin/sudo", "-n", "-u", bridge_user, "/bin/cat", str(probe.SUDOERS)],
        capture_output=True,
        check=False,
        text=True,
    )
    assert unreadable.returncode != 0
    authorized = subprocess.run(
        [
            "/usr/bin/sudo",
            "-n",
            "-u",
            bridge_user,
            "/usr/bin/sudo",
            "-n",
            "-H",
            "-u",
            "root",
            str(probe.BOUNDARY_HELPER),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert authorized.returncode == 0 and authorized.stdout == direct.stdout
    extra_argument = subprocess.run(
        [
            "/usr/bin/sudo",
            "-n",
            "-u",
            bridge_user,
            "/usr/bin/sudo",
            "-n",
            "-H",
            "-u",
            "root",
            str(probe.BOUNDARY_HELPER),
            "--alternate-path",
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert extra_argument.returncode != 0

    tampered = tmp_path / "hermes-email-boundary-verify"
    tampered.write_bytes(probe.BOUNDARY_HELPER.read_bytes() + b"\n")
    tampered.chmod(0o755)
    with pytest.raises(ValueError, match="helper bytes"):
        probe.verify_fixed_boundary(
            runtime,
            uid=0,
            gid=grp.getgrnam("wheel").gr_gid,
            helper=tampered,
            candidate_directory=probe.INSTALL_ROOT / "runtime",
            enforce_invoker=False,
        )


@pytest.mark.skipif(
    sys.platform != "darwin" or os.geteuid() != 0,
    reason="requires root and the installed dedicated macOS accounts",
)
def test_inference_uid_cannot_read_bridge_env_database_sidecars_or_credentials() -> None:
    probe = _load_probe()
    if not probe.BOUNDARY_HELPER.is_file():
        pytest.skip("fixed production boundary is not installed")
    direct = subprocess.run(
        [str(probe.BOUNDARY_HELPER)], capture_output=True, check=False, text=True
    )
    assert direct.returncode == 0 and direct.stderr == ""
    bridge_user = json.loads(direct.stdout)["bridge_user"]
    accounts = {name: pwd.getpwnam(name) for name in (bridge_user, "_hermesmail", "_hermesbuild")}
    root = Path(tempfile.mkdtemp(prefix="hermes-email-secret-canary.", dir="/private/tmp"))
    root.chmod(0o755)
    try:
        bridge = root / "bridge-private"
        inference = root / "inference-private"
        bridge.mkdir(mode=0o700)
        inference.mkdir(mode=0o700)
        os.chown(bridge, accounts[bridge_user].pw_uid, accounts[bridge_user].pw_gid)
        os.chown(inference, accounts["_hermesmail"].pw_uid, accounts["_hermesmail"].pw_gid)
        bridge_files = [
            bridge / "service.env",
            bridge / "bridge.db",
            bridge / "bridge.db-wal",
            bridge / "bridge.db-shm",
            bridge / "provider.credentials",
        ]
        inference_file = inference / "oauth.credentials"
        for path in bridge_files:
            path.write_text("SECRET-CANARY-BRIDGE\n")
            os.chown(path, accounts[bridge_user].pw_uid, accounts[bridge_user].pw_gid)
            path.chmod(0o600)
        inference_file.write_text("SECRET-CANARY-INFERENCE\n")
        os.chown(
            inference_file,
            accounts["_hermesmail"].pw_uid,
            accounts["_hermesmail"].pw_gid,
        )
        inference_file.chmod(0o600)

        def read_as(user: str, path: Path) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["/usr/bin/sudo", "-n", "-u", user, "/bin/cat", str(path)],
                capture_output=True,
                check=False,
                text=True,
            )

        assert all(read_as(bridge_user, path).returncode == 0 for path in bridge_files)
        assert read_as("_hermesmail", inference_file).returncode == 0
        assert all(read_as("_hermesmail", path).returncode != 0 for path in bridge_files)
        assert read_as(bridge_user, inference_file).returncode != 0
        assert all(read_as("_hermesbuild", path).returncode != 0 for path in bridge_files)
        assert read_as("_hermesbuild", inference_file).returncode != 0
    finally:
        shutil.rmtree(root)


@pytest.mark.parametrize(
    "arguments",
    [
        ["--source", "/tmp/source"],
        ["--python", "/tmp/venv/bin/python"],
        ["--wrapper", "/tmp/wrapper"],
        ["--helper", "/tmp/helper"],
    ],
)
def test_runtime_verifier_cli_rejects_arbitrary_runtime_paths(arguments: list[str]) -> None:
    with pytest.raises(SystemExit):
        _load_probe().main(arguments)
