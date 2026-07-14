#!/usr/bin/python3
# ruff: noqa: UP045 -- deployed system Python is macOS 3.9
"""Fail-closed handoff from an unverified v0.3 runtime to v0.4."""

from __future__ import annotations

import grp
import json
import os
import pwd
import re
import secrets
import stat
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

QUARANTINE_PREFIX = ".runtime-v0.3-quarantine."
TRANSACTION_PREFIX = ".runtime-"
TOKEN_PATTERN = re.compile(r"[0-9a-f]{24}")

AclValidator = Callable[[Sequence[Path]], None]
TokenFactory = Callable[[], str]
Renamer = Callable[[Path, Path], None]
DirectorySync = Callable[[Path], None]


@dataclass(frozen=True)
class MigrationPaths:
    filesystem_root: Path
    library: Path
    application_support: Path
    product_root: Path
    install_root: Path
    active_runtime: Path


def build_paths(filesystem_root: Path = Path("/")) -> MigrationPaths:
    library = filesystem_root / "Library"
    application_support = library / "Application Support"
    product_root = application_support / "HermesEmailAgent"
    install_root = product_root / "hermes-agent"
    return MigrationPaths(
        filesystem_root=filesystem_root,
        library=library,
        application_support=application_support,
        product_root=product_root,
        install_root=install_root,
        active_runtime=install_root / "runtime",
    )


def _validate_directory(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    exact_mode: Optional[int] = None,
) -> os.stat_result:
    details = path.lstat()
    if not stat.S_ISDIR(details.st_mode):
        raise ValueError("migration path is not a non-symlink directory")
    if details.st_uid != expected_uid or details.st_gid != expected_gid:
        raise ValueError("migration path has unsafe ownership")
    mode = stat.S_IMODE(details.st_mode)
    if exact_mode is not None and mode != exact_mode:
        raise ValueError("migration parent has an unsafe mode")
    if mode & 0o022:
        raise ValueError("migration path is group/other writable")
    return details


def reject_acls(paths: Sequence[Path]) -> None:
    result = subprocess.run(
        ["/bin/ls", "-lde", *(str(path) for path in paths)],
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("cannot inspect migration path ACLs")
    if any(
        (line.split() and line.split()[0].endswith("+")) or re.match(r"\s+\d+:", line) is not None
        for line in result.stdout.splitlines()
    ):
        raise ValueError("migration path has an unexpected ACL")


def _sync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _transaction_children(install_root: Path) -> list[Path]:
    return sorted(
        (child for child in install_root.iterdir() if child.name.startswith(TRANSACTION_PREFIX)),
        key=lambda child: child.name,
    )


def quarantine_runtime(
    paths: MigrationPaths,
    *,
    expected_uid: int,
    wheel_gid: int,
    admin_gid: int,
    require_root: bool = True,
    acl_validator: AclValidator = reject_acls,
    token_factory: TokenFactory = lambda: secrets.token_hex(12),
    renamer: Renamer = os.rename,
    directory_sync: DirectorySync = _sync_directory,
) -> Path:
    """Atomically quarantine the fixed legacy runtime without traversing its contents."""
    if paths != build_paths(paths.filesystem_root):
        raise ValueError("migration accepts only its fixed path plan")
    if require_root and os.geteuid() != 0:
        raise PermissionError("runtime migration requires root")

    parent_specs = (
        (paths.filesystem_root, expected_uid, wheel_gid),
        (paths.library, expected_uid, wheel_gid),
        (paths.application_support, expected_uid, admin_gid),
        (paths.product_root, expected_uid, wheel_gid),
        (paths.install_root, expected_uid, wheel_gid),
    )
    for path, uid, gid in parent_specs:
        _validate_directory(path, expected_uid=uid, expected_gid=gid, exact_mode=0o755)
    active_details = _validate_directory(
        paths.active_runtime,
        expected_uid=expected_uid,
        expected_gid=wheel_gid,
    )
    acl_validator([*(path for path, _uid, _gid in parent_specs), paths.active_runtime])

    if _transaction_children(paths.install_root):
        raise ValueError("runtime transaction or quarantine state already exists")
    token = token_factory()
    if TOKEN_PATTERN.fullmatch(token) is None:
        raise ValueError("migration token is invalid")
    quarantine = paths.install_root / (QUARANTINE_PREFIX + token)
    try:
        quarantine.lstat()
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError("runtime quarantine destination already exists")

    renamer(paths.active_runtime, quarantine)
    directory_sync(paths.install_root)

    try:
        paths.active_runtime.lstat()
    except FileNotFoundError:
        pass
    else:
        raise RuntimeError("active runtime remains after quarantine")
    quarantined_details = quarantine.lstat()
    if not stat.S_ISDIR(quarantined_details.st_mode):
        raise RuntimeError("quarantined runtime has an unsafe type")
    if (quarantined_details.st_dev, quarantined_details.st_ino) != (
        active_details.st_dev,
        active_details.st_ino,
    ):
        raise RuntimeError("quarantined runtime identity changed")
    return quarantine


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        print("runtime quarantine failed", file=sys.stderr)
        return 2
    try:
        quarantine = quarantine_runtime(
            build_paths(),
            expected_uid=pwd.getpwnam("root").pw_uid,
            wheel_gid=grp.getgrnam("wheel").gr_gid,
            admin_gid=grp.getgrnam("admin").gr_gid,
        )
    except Exception:
        print("runtime quarantine failed", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {"active": False, "quarantine": str(quarantine)},
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
