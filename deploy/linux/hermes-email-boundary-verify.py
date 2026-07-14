#!/usr/bin/python3
"""Root-only exact-byte verifier for the Linux Hermes email boundary."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

WRAPPER = Path("/usr/local/libexec/hermes-email-agent")
ADAPTER = Path("/opt/hermes-email-agent/runtime/hermes-email-agent-adapter.py")
PYTHON = Path("/opt/hermes-email-agent/runtime/venv/bin/python")
SUDOERS = Path("/etc/sudoers.d/hermes-email-agent")
WRAPPER_SHA256 = "093fe43ee637440592c03a5f8d7891ca6ac9c6800488d98acab09bf0ff5b9914"
ADAPTER_SHA256 = "69bbf6825ff523b925bf753c5e1202d6a69096f73c4c6f6881a36df5233f24c2"
_USER = r"[A-Za-z_][A-Za-z0-9_-]{0,31}"
_POLICY = re.compile(
    rf"Defaults:(?P<user>{_USER}) env_reset, secure_path=/usr/bin:/bin:/usr/sbin:/sbin\n"
    r"(?P=user) ALL = \(_hermesmail\) NOPASSWD: /usr/local/libexec/hermes-email-agent\n"
    r'(?P=user) ALL = \(root\) NOPASSWD: /usr/local/libexec/hermes-email-boundary-verify ""\n'
)


def _validate_parent_chain(path: Path) -> None:
    current = Path("/")
    for name in path.parent.parts[1:]:
        current /= name
        details = current.lstat()
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o022:
            raise ValueError("trusted parent chain is unsafe")


def _read_root_file(path: Path, mode: int) -> bytes:
    _validate_parent_chain(path)
    details = path.lstat()
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != 0
        or details.st_gid != 0
        or stat.S_IMODE(details.st_mode) != mode
    ):
        raise ValueError("trusted file metadata is unsafe")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if os.fstat(descriptor) != details:
            raise ValueError("trusted file changed during verification")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def verify() -> dict[str, str]:
    if os.geteuid() != 0:
        raise PermissionError("boundary verifier must run as root")
    wrapper = _read_root_file(WRAPPER, 0o755)
    adapter = _read_root_file(ADAPTER, 0o755)
    _read_root_file(PYTHON.resolve(strict=True), 0o755)
    policy = _read_root_file(SUDOERS, 0o440)
    if hashlib.sha256(wrapper).hexdigest() != WRAPPER_SHA256:
        raise ValueError("wrapper does not match reviewed bytes")
    if hashlib.sha256(adapter).hexdigest() != ADAPTER_SHA256:
        raise ValueError("adapter does not match reviewed bytes")
    try:
        match = _POLICY.fullmatch(policy.decode())
    except UnicodeDecodeError as exc:
        raise ValueError("sudoers is not UTF-8") from exc
    if match is None:
        raise ValueError("sudoers does not match reviewed policy")
    return {
        "adapter_sha256": ADAPTER_SHA256,
        "bridge_user": match.group("user"),
        "sudoers_sha256": hashlib.sha256(policy).hexdigest(),
        "wrapper_sha256": WRAPPER_SHA256,
    }


def main(arguments: list[str] | None = None) -> int:
    selected = sys.argv[1:] if arguments is None else arguments
    if selected:
        raise ValueError("boundary verifier accepts no arguments")
    print(json.dumps(verify(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, PermissionError, ValueError):
        print("Hermes email boundary verification failed", file=sys.stderr)
        raise SystemExit(1) from None
