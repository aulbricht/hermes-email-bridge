#!/usr/bin/python3
# ruff: noqa: UP045 -- deployed system Python is macOS 3.9
"""Root-only exact-byte verifier for the Hermes email sudo boundary."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Optional

WRAPPER = Path("/usr/local/libexec/hermes-email-agent")
SUDOERS = Path("/private/etc/sudoers.d/hermes-email-agent")
WRAPPER_SHA256 = "45f98b00e022a789fe168204da220e3146699c37a6368dfdf481a5f998c8985e"
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
_INFERENCE_USER = "_hermesmail"
_BUILD_USER = "_hermesbuild"
_INFERENCE_HOME = "/var/db/hermes-email-agent"
_FALSE_SHELL = "/usr/bin/false"


def validate_accounts(
    bridge_user: str,
    *,
    user_lookup: Optional[Callable[[str], pwd.struct_passwd]] = None,
    users: Optional[Callable[[], list[pwd.struct_passwd]]] = None,
    group_lookup: Optional[Callable[[str], grp.struct_group]] = None,
    gid_lookup: Optional[Callable[[int], grp.struct_group]] = None,
    groups: Optional[Callable[[], list[grp.struct_group]]] = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, object]:
    """Validate and return non-secret evidence for the dedicated macOS identities."""

    get_user = pwd.getpwnam if user_lookup is None else user_lookup
    get_users = pwd.getpwall if users is None else users
    get_group = grp.getgrnam if group_lookup is None else group_lookup
    get_gid = grp.getgrgid if gid_lookup is None else gid_lookup
    get_groups = grp.getgrall if groups is None else groups
    if re.fullmatch(_USER, bridge_user) is None or bridge_user in {
        "root",
        _INFERENCE_USER,
        _BUILD_USER,
    }:
        raise ValueError("bridge account name is unsafe")
    try:
        bridge = get_user(bridge_user)
        inference = get_user(_INFERENCE_USER)
        builder = get_user(_BUILD_USER)
        admin = get_group("admin")
        staff = get_group("staff")
        inference_group = get_group(_INFERENCE_USER)
    except KeyError as exc:
        raise ValueError("required dedicated account or group is missing") from exc
    if bridge.pw_name != bridge_user or bridge.pw_uid == 0:
        raise ValueError("bridge account identity is unsafe")
    if inference.pw_name != _INFERENCE_USER or builder.pw_name != _BUILD_USER:
        raise ValueError("fixed service account identity is unsafe")
    if len({0, bridge.pw_uid, inference.pw_uid, builder.pw_uid}) != 4:
        raise ValueError("dedicated account UIDs must be distinct and nonroot")
    if inference.pw_dir != _INFERENCE_HOME or inference.pw_shell != _FALSE_SHELL:
        raise ValueError("inference account home or shell is unsafe")
    if (
        inference.pw_gid in {admin.gr_gid, staff.gr_gid, bridge.pw_gid, builder.pw_gid}
        or inference_group.gr_gid != inference.pw_gid
        or inference_group.gr_mem
        or get_gid(inference.pw_gid).gr_name != _INFERENCE_USER
    ):
        raise ValueError("inference account primary group is unsafe")
    primary_users = {user.pw_name for user in get_users() if user.pw_gid == inference.pw_gid}
    if primary_users != {_INFERENCE_USER}:
        raise ValueError("inference primary group is not unique")
    supplementary = [group.gr_name for group in get_groups() if _INFERENCE_USER in group.gr_mem]
    if supplementary:
        raise ValueError("inference account has supplementary group memberships")
    hidden = runner(
        ["/usr/bin/dscl", ".", "-read", f"/Users/{_INFERENCE_USER}", "IsHidden"],
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
        text=True,
        timeout=30,
    )
    if hidden.returncode != 0 or hidden.stderr or hidden.stdout.strip() != "IsHidden: 1":
        raise ValueError("inference account is not hidden")
    for privileged_group in ("admin", "staff"):
        membership = runner(
            [
                "/usr/bin/dsmemberutil",
                "checkmembership",
                "-U",
                _INFERENCE_USER,
                "-G",
                privileged_group,
            ],
            capture_output=True,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
            text=True,
            timeout=30,
        )
        if (
            membership.returncode != 0
            or membership.stderr
            or not membership.stdout.strip().endswith("not a member of the group")
        ):
            raise ValueError("inference account has privileged group membership")
    return {
        "bridge_uid": bridge.pw_uid,
        "build_uid": builder.pw_uid,
        "inference_uid": inference.pw_uid,
        "inference_user": _INFERENCE_USER,
    }


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


def verify() -> dict[str, object]:
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
    accounts = validate_accounts(match.group("user"))
    return {
        "accounts": accounts,
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
