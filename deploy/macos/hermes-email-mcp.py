#!/usr/bin/env python3
"""Narrow MCP surface for one configured email identity."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

_MAX_OUTPUT_BYTES = 16_384
_MAX_TIMEOUT = 120.0

mcp = FastMCP("email-transport")


def _send_wrapper() -> Path:
    raw = os.environ.get("EMAIL_BRIDGE_SEND_WRAPPER", "")
    path = Path(raw)
    if not raw or not path.is_absolute():
        raise RuntimeError("EMAIL_BRIDGE_SEND_WRAPPER must be an absolute path")
    if path.name != "run-email-send.sh" or path.is_symlink() or path != path.resolve():
        raise RuntimeError("EMAIL_BRIDGE_SEND_WRAPPER is not an approved wrapper")
    try:
        details = path.stat()
    except OSError as exc:
        raise RuntimeError("EMAIL_BRIDGE_SEND_WRAPPER does not exist") from exc
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid not in {0, os.getuid()}
        or details.st_mode & 0o022
        or not details.st_mode & 0o111
    ):
        raise RuntimeError("EMAIL_BRIDGE_SEND_WRAPPER has unsafe metadata")
    for parent in path.parents:
        parent_details = parent.lstat()
        mode = stat.S_IMODE(parent_details.st_mode)
        root_sticky = parent_details.st_uid == 0 and bool(mode & stat.S_ISVTX)
        if (
            not stat.S_ISDIR(parent_details.st_mode)
            or parent_details.st_uid not in {0, os.getuid()}
            or (mode & 0o022 and not root_sticky)
        ):
            raise RuntimeError("EMAIL_BRIDGE_SEND_WRAPPER has an unsafe parent path")
    return path


def _timeout() -> float:
    try:
        value = float(os.environ.get("EMAIL_BRIDGE_SEND_TIMEOUT", "60"))
    except ValueError as exc:
        raise RuntimeError("EMAIL_BRIDGE_SEND_TIMEOUT is invalid") from exc
    if value <= 0 or value > _MAX_TIMEOUT:
        raise RuntimeError("EMAIL_BRIDGE_SEND_TIMEOUT must be between 0 and 120 seconds")
    return value


def _send(
    *,
    operation_id: str,
    to: str,
    subject: str,
    text: str | None,
    html: str | None,
) -> str:
    request = json.dumps(
        {
            "html": html,
            "operation_id": operation_id,
            "subject": subject,
            "text": text,
            "to": to,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    completed = subprocess.run(
        [str(_send_wrapper())],
        input=request,
        text=True,
        capture_output=True,
        check=False,
        timeout=_timeout(),
        env={
            "EMAIL_BRIDGE_ENV_FILE": os.environ.get("EMAIL_BRIDGE_ENV_FILE", ""),
            "HOME": os.environ.get("HOME", "/var/empty"),
            "LANG": "C.UTF-8",
            "PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
        },
    )
    if len(completed.stdout.encode()) > _MAX_OUTPUT_BYTES:
        raise RuntimeError("email send returned oversized output")
    if completed.returncode != 0:
        raise RuntimeError("email send failed; inspect the bridge operator log")
    try:
        response: Any = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("email send returned invalid output") from exc
    if (
        type(response) is not dict
        or set(response) != {"duplicate", "provider_message_id"}
        or type(response.get("duplicate")) is not bool
        or type(response.get("provider_message_id")) is not str
        or not response["provider_message_id"]
    ):
        raise RuntimeError("email send returned an invalid result")
    return json.dumps(response, sort_keys=True)


@mcp.tool()
def email_send(
    operation_id: str,
    to: str,
    subject: str,
    text: str | None = None,
    html: str | None = None,
) -> str:
    """Send one email using a stable operation ID and the configured identity."""

    return _send(
        operation_id=operation_id,
        to=to,
        subject=subject,
        text=text,
        html=html,
    )


if __name__ == "__main__":
    mcp.run()
