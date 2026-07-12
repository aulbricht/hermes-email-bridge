#!/usr/bin/python3
"""Root-only exact-byte verifier for the Hermes email sudo boundary."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

WRAPPER = Path("/usr/local/libexec/hermes-email-agent")
SUDOERS = Path("/private/etc/sudoers.d/hermes-email-agent")
WRAPPER_SHA256 = "52c610e34d1156a0fa3bd60834940da56d10503d16b1d4589fe012ea6826d79c"
_USER = r"[A-Za-z_][A-Za-z0-9_-]{0,31}"
_POLICY = re.compile(
    rf"Defaults:(?P<user>{_USER}) env_reset, secure_path=/usr/bin:/bin:/usr/sbin:/sbin\n"
    r"(?P=user) ALL = \(_hermesmail\) NOPASSWD: /usr/local/libexec/hermes-email-agent\n"
    r'(?P=user) ALL = \(root\) NOPASSWD: /usr/local/libexec/hermes-email-boundary-verify ""\n'
)
_TEMPLATE = (
    "Defaults:{user} env_reset, secure_path=/usr/bin:/bin:/usr/sbin:/sbin\n"
    "{user} ALL = (_hermesmail) NOPASSWD: /usr/local/libexec/hermes-email-agent\n"
    '{user} ALL = (root) NOPASSWD: /usr/local/libexec/hermes-email-boundary-verify ""\n'
)


def _reject_acl(path: Path) -> None:
    acl = subprocess.run(
        ["/bin/ls", "-lde", str(path)],
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        text=True,
        timeout=30,
    )
    lines = acl.stdout.splitlines()
    if (
        acl.returncode != 0
        or acl.stderr
        or not lines
        or lines[0].split()[0].endswith("+")
        or any(re.match(r"\s+\d+:", line) for line in lines[1:])
    ):
        raise ValueError("fixed boundary path has an unexpected ACL")


def _validate_directory(path: Path) -> None:
    details = path.lstat()
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != 0
        or details.st_gid != grp.getgrnam("wheel").gr_gid
        or stat.S_IMODE(details.st_mode) != 0o755
    ):
        raise ValueError("fixed boundary directory has unsafe metadata")
    _reject_acl(path)


def _read_fixed(path: Path, mode: int) -> bytes:
    details = path.lstat()
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != 0
        or details.st_gid != grp.getgrnam("wheel").gr_gid
        or stat.S_IMODE(details.st_mode) != mode
    ):
        raise ValueError("fixed boundary file has unsafe metadata")
    _reject_acl(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if os.fstat(descriptor) != details:
            raise ValueError("fixed boundary file changed during verification")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def verify() -> dict[str, str]:
    if os.geteuid() != 0:
        raise PermissionError("boundary helper must run as root")
    wrapper = _read_fixed(WRAPPER, 0o755)
    if hashlib.sha256(wrapper).hexdigest() != WRAPPER_SHA256:
        raise ValueError("installed wrapper does not match the reviewed bytes")
    for directory in (Path("/"), Path("/private"), Path("/private/etc"), SUDOERS.parent):
        _validate_directory(directory)
    sudoers = _read_fixed(SUDOERS, 0o440)
    try:
        policy = sudoers.decode()
    except UnicodeDecodeError as exc:
        raise ValueError("installed sudoers policy is not UTF-8") from exc
    match = _POLICY.fullmatch(policy)
    if match is None or policy != _TEMPLATE.format(user=match.group("user")):
        raise ValueError("installed sudoers policy does not match the reviewed bytes")
    return {
        "bridge_user": match.group("user"),
        "sudoers_sha256": hashlib.sha256(sudoers).hexdigest(),
        "wrapper_sha256": WRAPPER_SHA256,
    }


def main(arguments: list[str] | None = None) -> int:
    if arguments is None:
        arguments = sys.argv[1:]
    if arguments:
        raise ValueError("boundary helper accepts no arguments")
    print(json.dumps(verify(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, PermissionError, RuntimeError, ValueError):
        print("Hermes email boundary verification failed", file=sys.stderr)
        raise SystemExit(1) from None
