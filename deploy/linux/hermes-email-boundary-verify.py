#!/usr/bin/python3
"""Root-only exact-byte verifier for the Linux Hermes email boundary."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import re
import stat
import sys
from collections.abc import Callable
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
_INFERENCE_USER = "_hermesmail"
_BRIDGE_HOME = "/var/lib/hermes-email-bridge"
_INFERENCE_HOME = "/var/lib/hermes-email-agent"
_NOLOGIN_SHELL = "/usr/sbin/nologin"
_PRIVILEGED_GROUPS = {"root", "wheel", "sudo", "admin", "staff"}


def validate_accounts(
    bridge_user: str,
    *,
    user_lookup: Callable[[str], pwd.struct_passwd] | None = None,
    users: Callable[[], list[pwd.struct_passwd]] | None = None,
    group_lookup: Callable[[str], grp.struct_group] | None = None,
    gid_lookup: Callable[[int], grp.struct_group] | None = None,
    groups: Callable[[], list[grp.struct_group]] | None = None,
) -> dict[str, object]:
    """Validate dedicated Linux service identities and return non-secret evidence."""

    get_user = pwd.getpwnam if user_lookup is None else user_lookup
    get_users = pwd.getpwall if users is None else users
    get_group = grp.getgrnam if group_lookup is None else group_lookup
    get_gid = grp.getgrgid if gid_lookup is None else gid_lookup
    get_groups = grp.getgrall if groups is None else groups
    if re.fullmatch(_USER, bridge_user) is None or bridge_user in {"root", _INFERENCE_USER}:
        raise ValueError("bridge account name is unsafe")
    try:
        bridge = get_user(bridge_user)
        inference = get_user(_INFERENCE_USER)
        bridge_group = get_group(bridge_user)
        inference_group = get_group(_INFERENCE_USER)
    except KeyError as exc:
        raise ValueError("required dedicated Linux account or group is missing") from exc
    if bridge.pw_name != bridge_user or inference.pw_name != _INFERENCE_USER:
        raise ValueError("dedicated Linux account identity is unsafe")
    if len({0, bridge.pw_uid, inference.pw_uid}) != 3:
        raise ValueError("dedicated Linux account UIDs must be distinct and nonroot")
    if bridge.pw_dir != _BRIDGE_HOME or bridge.pw_shell != _NOLOGIN_SHELL:
        raise ValueError("bridge account home or shell is unsafe")
    if inference.pw_dir != _INFERENCE_HOME or inference.pw_shell != _NOLOGIN_SHELL:
        raise ValueError("inference account home or shell is unsafe")
    if bridge.pw_dir == inference.pw_dir:
        raise ValueError("dedicated Linux account homes must not overlap")
    all_groups = get_groups()
    privileged_gids = {
        group.gr_gid for group in all_groups if group.gr_name in _PRIVILEGED_GROUPS
    } | {0}
    if bridge.pw_gid in privileged_gids or inference.pw_gid in privileged_gids:
        raise ValueError("dedicated Linux account primary group is privileged")
    if (
        bridge_group.gr_gid != bridge.pw_gid
        or inference_group.gr_gid != inference.pw_gid
        or bridge_group.gr_mem
        or inference_group.gr_mem
        or get_gid(bridge.pw_gid).gr_name != bridge_user
        or get_gid(inference.pw_gid).gr_name != _INFERENCE_USER
        or bridge.pw_gid == inference.pw_gid
    ):
        raise ValueError("dedicated Linux primary group is unsafe")
    primary_owners = {
        bridge.pw_gid: {user.pw_name for user in get_users() if user.pw_gid == bridge.pw_gid},
        inference.pw_gid: {user.pw_name for user in get_users() if user.pw_gid == inference.pw_gid},
    }
    if primary_owners != {
        bridge.pw_gid: {bridge_user},
        inference.pw_gid: {_INFERENCE_USER},
    }:
        raise ValueError("dedicated Linux primary group is not unique")
    for account in (bridge_user, _INFERENCE_USER):
        memberships = [group.gr_name for group in all_groups if account in group.gr_mem]
        if memberships:
            raise ValueError("dedicated Linux account has supplementary group memberships")
    return {
        "bridge_uid": bridge.pw_uid,
        "inference_uid": inference.pw_uid,
        "inference_user": _INFERENCE_USER,
    }


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


def verify() -> dict[str, object]:
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
    accounts = validate_accounts(match.group("user"))
    return {
        "accounts": accounts,
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
