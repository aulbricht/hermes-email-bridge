#!/usr/bin/python3
"""Root-installed fixed invocation boundary for email-driven Hermes."""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Sequence

HERMES = "/Library/Application Support/HermesEmailAgent/hermes-agent/venv/bin/hermes"
STATE_DIR = "/var/db/hermes-email-agent"
WORKSPACE = "/var/db/hermes-email-agent/workspace"
_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
_BASE_ARGV = (
    HERMES,
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
)
_ENV = {
    "HOME": STATE_DIR,
    "HERMES_HOME": STATE_DIR,
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LANG": "en_US.UTF-8",
    "PYTHONDONTWRITEBYTECODE": "1",
}


def build_invocation(arguments: Sequence[str]) -> tuple[str, tuple[str, ...], dict[str, str]]:
    """Validate the only two runner shapes and return fixed execve inputs."""

    resume: str | None = None
    if len(arguments) == 2 and arguments[0] == "--query":
        query = arguments[1]
    elif len(arguments) == 4 and arguments[0] == "--resume" and arguments[2] == "--query":
        resume = arguments[1]
        query = arguments[3]
    else:
        raise ValueError("expected --query TEXT with one optional --resume SESSION_ID")
    if not query or query.startswith("-"):
        raise ValueError("query cannot be empty or option-like")
    if resume is not None and _SESSION_ID.fullmatch(resume) is None:
        raise ValueError("session ID is invalid")
    suffix = ("--resume", resume) if resume is not None else ()
    return WORKSPACE, (*_BASE_ARGV, *suffix, "--query", query), dict(_ENV)


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        cwd, argv, env = build_invocation(sys.argv[1:] if arguments is None else arguments)
    except ValueError as exc:
        print(f"hermes-email-agent: {exc}", file=sys.stderr)
        return 64
    os.chdir(cwd)
    os.execve(HERMES, list(argv), env)
    return 70  # pragma: no cover - execve replaces the process


if __name__ == "__main__":
    raise SystemExit(main())
