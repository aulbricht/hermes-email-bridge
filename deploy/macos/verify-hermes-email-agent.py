#!/usr/bin/python3
# ruff: noqa: UP045 -- deployed system Python is macOS 3.9
"""Verify pinned Hermes source, zero-schema runtime, wrapper contract, and optional live resume."""

from __future__ import annotations

import argparse
import json
import re
import runpy
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Optional

INSTALL_ROOT = Path("/Library/Application Support/HermesEmailAgent/hermes-agent")
SOURCE = INSTALL_ROOT / "source"
VENV_PYTHON = INSTALL_ROOT / "venv/bin/python"
WRAPPER = Path("/usr/local/libexec/hermes-email-agent")
FETCHER = Path(__file__).with_name("fetch-hermes-email-agent.py")
_SESSION = re.compile(r"(?m)^session_id:\s*([A-Za-z0-9][A-Za-z0-9_-]{0,127})\s*$")
_RUNTIME_CODE = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
import toolsets
assert toolsets.validate_toolset("context_engine") is True
assert toolsets.resolve_toolset("context_engine") == []
from model_tools import get_tool_definitions
definitions = get_tool_definitions(enabled_toolsets=["context_engine"], quiet_mode=True)
assert definitions == []
print(json.dumps({"tool_schemas": len(definitions), "toolset": "context_engine"}, sort_keys=True))
"""
_SOURCE_CODE = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
import toolsets
assert toolsets.validate_toolset("context_engine") is True
resolved = toolsets.resolve_toolset("context_engine")
assert resolved == []
print(json.dumps({"resolved_tools": len(resolved), "toolset": "context_engine"}, sort_keys=True))
"""


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


def verify_runtime(
    source: Path,
    python: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    result = runner(
        [str(python), "-I", "-c", _RUNTIME_CODE, str(source)],
        capture_output=True,
        check=False,
        env={
            "HOME": "/var/db/hermes-email-agent",
            "HERMES_HOME": "/var/db/hermes-email-agent",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise ValueError("Hermes zero-schema runtime probe failed")
    if result.stderr or json.loads(result.stdout) != {
        "tool_schemas": 0,
        "toolset": "context_engine",
    }:
        raise ValueError("Hermes zero-schema runtime probe returned unexpected output")


def verify_source_toolset(
    source: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    result = runner(
        ["/usr/bin/python3", "-I", "-c", _SOURCE_CODE, str(source)],
        capture_output=True,
        check=False,
        env={
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        text=True,
        timeout=60,
    )
    if result.returncode != 0 or result.stderr:
        raise ValueError("Hermes pinned-source toolset probe failed")
    if json.loads(result.stdout) != {"resolved_tools": 0, "toolset": "context_engine"}:
        raise ValueError("Hermes pinned-source toolset probe returned unexpected output")


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


def verify_provenance(source: Path) -> None:
    result = subprocess.run(
        ["/usr/bin/python3", str(FETCHER), "--target", str(source), "--verify"],
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise ValueError("Hermes source provenance verification failed")


def main(arguments: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--python", type=Path, default=VENV_PYTHON)
    parser.add_argument("--wrapper", type=Path, default=WRAPPER)
    parser.add_argument("--live", action="store_true")
    parser.add_argument(
        "--source-only",
        action="store_true",
        help="verify provenance/toolset source before the pinned venv is installed",
    )
    args = parser.parse_args(arguments)
    verify_provenance(args.source)
    verify_wrapper_shapes(args.wrapper)
    if args.source_only:
        verify_source_toolset(args.source)
    else:
        verify_runtime(args.source, args.python)
    if args.live:
        verify_live()
    print(
        json.dumps(
            {
                "live": args.live,
                "provenance": "verified",
                "source_only": args.source_only,
                "tool_schemas": None if args.source_only else 0,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
