#!/usr/bin/python3
# ruff: noqa: UP045 -- deployed system Python is macOS 3.9
"""Verify the fixed Hermes runtime attestation and optionally run a live canary."""

from __future__ import annotations

import argparse
import grp
import hashlib
import importlib.util
import json
import os
import pwd
import re
import runpy
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Optional

INSTALL_ROOT = Path("/Library/Application Support/HermesEmailAgent/hermes-agent")
WRAPPER = Path("/usr/local/libexec/hermes-email-agent")
BOUNDARY_HELPER = Path("/usr/local/libexec/hermes-email-boundary-verify")
SUDOERS = Path("/private/etc/sudoers.d/hermes-email-agent")
RUNTIME_INSTALLER = Path(__file__).with_name("install-hermes-email-runtime.py")
_SESSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
_BRIDGE_USER = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,31}")
_PLACEHOLDER = "__BRIDGE_USER__"


def _runtime_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "hermes_email_runtime_installer", RUNTIME_INSTALLER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load fixed runtime verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def verify_wrapper_shapes(wrapper: Path) -> None:
    namespace = runpy.run_path(str(wrapper))
    build = namespace.get("build_invocation")
    if not callable(build):
        raise ValueError("installed wrapper does not expose build_invocation")
    _cwd, fresh, _env = build(["--query", "probe"])
    _cwd, resumed, _env = build(["--resume", "probe_session", "--query", "probe"])
    expected = (
        "/Library/Application Support/HermesEmailAgent/hermes-agent/runtime/venv/bin/python",
        "-I",
        "-B",
        "/Library/Application Support/HermesEmailAgent/hermes-agent/runtime/"
        "hermes-email-agent-adapter.py",
    )
    if fresh[:4] != expected or resumed[:4] != expected:
        raise ValueError("wrapper does not pin the programmatic adapter")
    if "--resume" in fresh or resumed[-4:-2] != ("--resume", "probe_session"):
        raise ValueError("wrapper new/resume argument contract is invalid")


def verify_adapter_shape(adapter: Path) -> None:
    namespace = runpy.run_path(str(adapter))
    if (
        namespace.get("PROTOCOL") != "hermes-email-bridge/2"
        or namespace.get("HERMES_VERSION") != "0.18.2"
        or namespace.get("MODEL") != "gpt-5.5"
        or namespace.get("PROVIDER") != "openai-codex"
        or namespace.get("TOOLSETS") != ["context_engine"]
        or namespace.get("MAX_TURNS") != 1
        or namespace.get("NORMAL_TURN_EXIT_REASON") != "text_response(finish_reason=stop)"
    ):
        raise ValueError("adapter does not pin the reviewed programmatic contract")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def verify_fixed_boundary(
    runtime: Any,
    *,
    uid: int,
    gid: int,
    wrapper: Path = WRAPPER,
    helper: Path = BOUNDARY_HELPER,
    candidate_directory: Optional[Path] = None,
    enforce_invoker: bool = True,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    account_validator: Optional[Callable[[str], dict[str, object]]] = None,
) -> dict[str, str]:
    candidates = Path(__file__).parent if candidate_directory is None else candidate_directory
    candidate_wrapper = candidates / "hermes-email-agent-wrapper.py"
    candidate_adapter = candidates / "hermes-email-agent-adapter.py"
    candidate_sudoers = candidates / "hermes-email-agent.sudoers"
    candidate_helper = candidates / "hermes-email-boundary-verify.py"
    candidate_wrapper_content = candidate_wrapper.read_bytes()
    candidate_adapter_content = candidate_adapter.read_bytes()
    candidate_sudoers_content = candidate_sudoers.read_bytes()
    candidate_helper_content = candidate_helper.read_bytes()
    if _sha256(candidate_wrapper_content) != runtime.WRAPPER_SHA256:
        raise ValueError("attested wrapper candidate does not match the reviewed hash")
    if _sha256(candidate_adapter_content) != runtime.ADAPTER_SHA256:
        raise ValueError("attested adapter candidate does not match the reviewed hash")
    if _sha256(candidate_sudoers_content) != runtime.SUDOERS_TEMPLATE_SHA256:
        raise ValueError("attested sudoers candidate does not match the reviewed hash")
    if _sha256(candidate_helper_content) != runtime.BOUNDARY_HELPER_SHA256:
        raise ValueError("attested boundary helper does not match the reviewed hash")
    if wrapper == WRAPPER:
        runtime.verify_usr_local_chain(wrapper, uid=uid, gid=gid)
    runtime._safe_details(wrapper, expected_uid=uid, expected_gid=gid, exact_mode=0o755)
    wrapper_content = wrapper.read_bytes()
    if wrapper_content != candidate_wrapper_content:
        raise ValueError("installed wrapper bytes do not match the attested candidate")
    runtime.reject_acls([wrapper])
    if helper == BOUNDARY_HELPER:
        runtime.verify_usr_local_chain(helper, uid=uid, gid=gid)
    runtime._safe_details(helper, expected_uid=uid, expected_gid=gid, exact_mode=0o755)
    if helper.read_bytes() != candidate_helper_content:
        raise ValueError("installed boundary helper bytes do not match the attested candidate")
    runtime.reject_acls([helper])
    command = (
        [str(helper)]
        if os.geteuid() == 0
        else ["/usr/bin/sudo", "-n", "-H", "-u", "root", str(helper)]
    )
    result = runner(
        command,
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
        text=True,
        timeout=60,
    )
    if result.returncode != 0 or result.stderr:
        raise ValueError("privileged boundary attestation failed")
    try:
        template = candidate_sudoers_content.decode()
        evidence = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("privileged boundary attestation is malformed") from exc
    if not isinstance(evidence, dict) or set(evidence) != {
        "accounts",
        "bridge_user",
        "sudoers_sha256",
        "wrapper_sha256",
    }:
        raise ValueError("privileged boundary attestation is incomplete")
    bridge_user = evidence.get("bridge_user")
    if not isinstance(bridge_user, str) or _BRIDGE_USER.fullmatch(bridge_user) is None:
        raise ValueError("privileged boundary bridge user is malformed")
    if template.count(_PLACEHOLDER) != 3:
        raise ValueError("attested sudoers template is malformed")
    if account_validator is None:
        helper_namespace = runpy.run_path(str(candidate_helper))
        validator = helper_namespace.get("validate_accounts")
        if not callable(validator):
            raise ValueError("attested boundary helper lacks account validation")
        account_evidence = validator(bridge_user)
    else:
        account_evidence = account_validator(bridge_user)
    expected = {
        "accounts": account_evidence,
        "bridge_user": bridge_user,
        "sudoers_sha256": _sha256(template.replace(_PLACEHOLDER, bridge_user).encode()),
        "wrapper_sha256": runtime.WRAPPER_SHA256,
    }
    if (
        evidence != expected
        or result.stdout != json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n"
    ):
        raise ValueError("privileged boundary attestation does not match reviewed bytes")
    if enforce_invoker and os.geteuid() != 0 and pwd.getpwuid(os.getuid()).pw_name != bridge_user:
        raise ValueError("startup verifier user does not match the sudoers bridge user")
    verify_wrapper_shapes(wrapper)
    verify_adapter_shape(candidate_adapter)
    return {
        "adapter_sha256": runtime.ADAPTER_SHA256,
        "bridge_user": bridge_user,
        "sudoers_sha256": expected["sudoers_sha256"],
        "wrapper_sha256": expected["wrapper_sha256"],
    }


def _live_call(
    arguments: list[str],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> subprocess.CompletedProcess[str]:
    return runner(
        ["/usr/bin/sudo", "-n", "-H", "-u", "_hermesmail", str(WRAPPER), *arguments],
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
        text=True,
        timeout=180,
    )


def _parse_protocol(result: subprocess.CompletedProcess[str]) -> dict[str, str]:
    if result.returncode != 0 or result.stderr:
        raise ValueError("Hermes live protocol failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("Hermes live protocol is malformed") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "action",
        "protocol",
        "reply",
        "session_id",
    }:
        raise ValueError("Hermes live protocol has an invalid shape")
    reply = payload.get("reply")
    session_id = payload.get("session_id")
    if (
        payload.get("protocol") != "hermes-email-bridge/2"
        or payload.get("action") != "reply"
        or not isinstance(reply, str)
        or not reply.strip()
        or not isinstance(session_id, str)
        or _SESSION.fullmatch(session_id) is None
    ):
        raise ValueError("Hermes live protocol fields are invalid")
    canonical = (
        json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
    )
    if result.stdout != canonical:
        raise ValueError("Hermes live protocol is not canonical")
    return {"reply": reply, "session_id": session_id}


def verify_live(
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    fresh = _live_call(
        [
            "--query",
            'Return exactly: {"action":"reply","reply":"EMAIL_BRIDGE_PROBE_OK"}',
        ],
        runner=runner,
    )
    fresh_payload = _parse_protocol(fresh)
    if fresh_payload["reply"] != "EMAIL_BRIDGE_PROBE_OK":
        raise ValueError("Hermes live new-session probe failed")
    resumed = _live_call(
        [
            "--resume",
            fresh_payload["session_id"],
            "--query",
            'Return exactly: {"action":"reply","reply":"EMAIL_BRIDGE_RESUME_OK"}',
        ],
        runner=runner,
    )
    resumed_payload = _parse_protocol(resumed)
    if resumed_payload["reply"] != "EMAIL_BRIDGE_RESUME_OK":
        raise ValueError("Hermes live resumed-session probe failed")


def main(arguments: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args(arguments)
    runtime = _runtime_module()
    uid = pwd.getpwnam("root").pw_uid
    gid = grp.getgrnam("wheel").gr_gid
    runtime.verify_source_cli()
    evidence = runtime.verify_attestation(runtime.build_paths(), uid=uid, gid=gid)
    boundary = verify_fixed_boundary(runtime, uid=uid, gid=gid)
    if args.live:
        verify_live()
    print(
        json.dumps(
            {
                "attestation": "verified",
                "live_canary": args.live,
                "bridge_user": boundary["bridge_user"],
                "tool_schemas": evidence["tool_schemas"],
                "version": evidence["version"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, RuntimeError, ValueError) as exc:
        print(f"Hermes runtime verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
