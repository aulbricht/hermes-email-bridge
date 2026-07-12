#!/usr/bin/python3
# ruff: noqa: UP045 -- deployed system Python is macOS 3.9
"""Verify the fixed Hermes runtime attestation and optionally run a live canary."""

from __future__ import annotations

import argparse
import grp
import importlib.util
import json
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
RUNTIME_INSTALLER = Path(__file__).with_name("install-hermes-email-runtime.py")
_SESSION = re.compile(r"(?m)^session_id:\s*([A-Za-z0-9][A-Za-z0-9_-]{0,127})\s*$")


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
    for argv in (fresh, resumed):
        index = argv.index("--toolsets")
        if argv[index + 1] != "context_engine":
            raise ValueError("wrapper does not pin context_engine")
    if "--resume" in fresh or resumed[-4:-2] != ("--resume", "probe_session"):
        raise ValueError("wrapper new/resume argument contract is invalid")


def verify_fixed_wrapper(runtime: Any, *, uid: int, gid: int) -> None:
    runtime.verify_usr_local_chain(WRAPPER, uid=uid, gid=gid)
    runtime._safe_details(WRAPPER, expected_uid=uid, expected_gid=gid, exact_mode=0o755)
    runtime.reject_acls([WRAPPER])
    verify_wrapper_shapes(WRAPPER)


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


def verify_live(
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    fresh = _live_call(["--query", "Reply with exactly: EMAIL_BRIDGE_PROBE_OK"], runner=runner)
    if fresh.returncode != 0 or fresh.stdout.strip() != "EMAIL_BRIDGE_PROBE_OK":
        raise ValueError("Hermes live new-session probe failed")
    match = _SESSION.fullmatch(fresh.stderr.strip())
    if match is None or "warning" in fresh.stderr.lower():
        raise ValueError("Hermes live probe did not emit a session ID")
    resumed = _live_call(
        ["--resume", match.group(1), "--query", "Reply with exactly: EMAIL_BRIDGE_RESUME_OK"],
        runner=runner,
    )
    if resumed.returncode != 0 or resumed.stdout.strip() != "EMAIL_BRIDGE_RESUME_OK":
        raise ValueError("Hermes live resumed-session probe failed")
    resumed_match = _SESSION.fullmatch(resumed.stderr.strip())
    if (
        resumed_match is None
        or resumed_match.group(1) != match.group(1)
        or "warning" in resumed.stderr.lower()
    ):
        raise ValueError("Hermes live resume did not preserve the session ID")


def main(arguments: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args(arguments)
    runtime = _runtime_module()
    uid = pwd.getpwnam("root").pw_uid
    gid = grp.getgrnam("wheel").gr_gid
    runtime.verify_source_cli()
    evidence = runtime.verify_attestation(runtime.build_paths(), uid=uid, gid=gid)
    verify_fixed_wrapper(runtime, uid=uid, gid=gid)
    if args.live:
        verify_live()
    print(
        json.dumps(
            {
                "attestation": "verified",
                "live_canary": args.live,
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
