#!/usr/bin/python3
# ruff: noqa: UP045 -- deployed system Python is macOS 3.9
"""Fail-closed installer for the macOS Hermes email isolation boundary."""

from __future__ import annotations

import argparse
import grp
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_BRIDGE_USER = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,31}")
_PLACEHOLDER = "__BRIDGE_USER__"


@dataclass(frozen=True)
class InstallPlan:
    wrapper_source: Path
    helper_source: Path
    sudoers_source: Path
    filesystem_root: Path
    usr: Path
    usr_local: Path
    libexec: Path
    wrapper_destination: Path
    helper_destination: Path
    private: Path
    etc: Path
    sudoers_directory: Path
    sudoers_destination: Path


def build_plan(root: Path = Path("/"), assets: Optional[Path] = None) -> InstallPlan:
    asset_directory = Path(__file__).parent if assets is None else assets

    def rooted(path: str) -> Path:
        return root / path.removeprefix("/")

    libexec = rooted("/usr/local/libexec")
    sudoers_directory = rooted("/private/etc/sudoers.d")
    return InstallPlan(
        wrapper_source=asset_directory / "hermes-email-agent-wrapper.py",
        helper_source=asset_directory / "hermes-email-boundary-verify.py",
        sudoers_source=asset_directory / "hermes-email-agent.sudoers",
        filesystem_root=root,
        usr=rooted("/usr"),
        usr_local=rooted("/usr/local"),
        libexec=libexec,
        wrapper_destination=libexec / "hermes-email-agent",
        helper_destination=libexec / "hermes-email-boundary-verify",
        private=rooted("/private"),
        etc=rooted("/private/etc"),
        sudoers_directory=sudoers_directory,
        sudoers_destination=sudoers_directory / "hermes-email-agent",
    )


def validate_bridge_user(value: str) -> str:
    if _BRIDGE_USER.fullmatch(value) is None:
        raise ValueError("bridge user must be a narrow local account name")
    return value


def render_sudoers(template: str, bridge_user: str) -> str:
    validate_bridge_user(bridge_user)
    if template.count(_PLACEHOLDER) != 3:
        raise ValueError("sudoers template must contain exactly three bridge-user placeholders")
    rendered = template.replace(_PLACEHOLDER, bridge_user)
    if _PLACEHOLDER in rendered or re.search(r"__[A-Z0-9_]+__", rendered):
        raise ValueError("sudoers placeholder rendering failed")
    return rendered


def has_unexpected_acl(path: Path) -> bool:
    result = subprocess.run(
        ["/bin/ls", "-lde", str(path)],
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"cannot inspect ACL for {path}")
    lines = result.stdout.splitlines()
    permissions = lines[0].split()[0] if lines else ""
    return permissions.endswith("+") or any(re.match(r"\s+\d+:", line) for line in lines[1:])


def validate_path(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    directory: bool,
    exact_mode: Optional[int] = None,
    acl_checker: Callable[[Path], bool] = has_unexpected_acl,
) -> None:
    try:
        details = path.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"required trusted path is missing: {path}") from exc
    if stat.S_ISLNK(details.st_mode):
        raise ValueError(f"trusted path cannot be a symlink: {path}")
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(details.st_mode):
        raise ValueError(f"trusted path has the wrong type: {path}")
    if details.st_uid != expected_uid or details.st_gid != expected_gid:
        raise ValueError(f"trusted path has unsafe ownership: {path}")
    mode = stat.S_IMODE(details.st_mode)
    if exact_mode is not None and mode != exact_mode:
        raise ValueError(f"trusted path must have mode {exact_mode:04o}: {path}")
    if mode & 0o022:
        raise ValueError(f"trusted path cannot be group/other writable: {path}")
    if acl_checker(path):
        raise ValueError(f"trusted path has an unexpected ACL: {path}")


def _read_source(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"cannot safely open installation source: {path}") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"installation source must be a regular non-symlink: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def _validate_sudoers(rendered: str, validator: Callable[[Path], None]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix="hermes-email-agent-sudoers.")
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        validator(temporary)
    finally:
        temporary.unlink(missing_ok=True)


def run_visudo(path: Path) -> None:
    result = subprocess.run(
        ["/usr/sbin/visudo", "-cf", str(path)],
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
        text=True,
    )
    if result.returncode != 0:
        raise ValueError("rendered sudoers policy failed visudo validation")


def _stage_file(
    directory: Path, name: str, content: bytes, *, uid: int, gid: int, mode: int
) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{name}.", dir=directory)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        return temporary
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _restore(
    destination: Path,
    backup: Optional[Path],
    *,
    replaced: bool,
) -> None:
    if not replaced:
        return
    if backup is None:
        destination.unlink(missing_ok=True)
    else:
        os.replace(backup, destination)


def install(
    plan: InstallPlan,
    bridge_user: str,
    *,
    expected_uid: int,
    expected_gid: int,
    mutate: bool,
    require_root: bool = True,
    acl_checker: Callable[[Path], bool] = has_unexpected_acl,
    sudoers_validator: Callable[[Path], None] = run_visudo,
    replacer: Callable[[Path, Path], None] = os.replace,
) -> tuple[str, ...]:
    bridge_user = validate_bridge_user(bridge_user)
    wrapper_content = _read_source(plan.wrapper_source)
    helper_content = _read_source(plan.helper_source)
    try:
        sudoers_template = _read_source(plan.sudoers_source).decode()
    except UnicodeDecodeError as exc:
        raise ValueError("sudoers template must be UTF-8 text") from exc
    rendered_sudoers = render_sudoers(sudoers_template, bridge_user)

    for trusted_directory in (
        plan.filesystem_root,
        plan.usr,
        plan.usr_local,
        plan.private,
        plan.etc,
        plan.sudoers_directory,
    ):
        validate_path(
            trusted_directory,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            directory=True,
            exact_mode=0o755,
            acl_checker=acl_checker,
        )
    try:
        plan.libexec.lstat()
    except FileNotFoundError:
        libexec_missing = True
    else:
        libexec_missing = False
    if not libexec_missing:
        validate_path(
            plan.libexec,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            directory=True,
            exact_mode=0o755,
            acl_checker=acl_checker,
        )
    for destination, mode in (
        (plan.wrapper_destination, 0o755),
        (plan.helper_destination, 0o755),
        (plan.sudoers_destination, 0o440),
    ):
        if destination.exists() or destination.is_symlink():
            validate_path(
                destination,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                directory=False,
                exact_mode=mode,
                acl_checker=acl_checker,
            )
    _validate_sudoers(rendered_sudoers, sudoers_validator)

    actions_list: list[str] = []
    if libexec_missing:
        actions_list.append(f"create {plan.libexec} root:wheel 0755")
    actions_list.extend(
        (
            f"install {plan.wrapper_destination} root:wheel 0755",
            f"install {plan.helper_destination} root:wheel 0755",
            f"install {plan.sudoers_destination} root:wheel 0440",
        )
    )
    actions = tuple(actions_list)
    if not mutate:
        return actions
    if require_root and os.geteuid() != 0:
        raise PermissionError("installation must run as root")
    wrapper_stage = _stage_file(
        plan.usr_local,
        "hermes-email-agent.new",
        wrapper_content,
        uid=expected_uid,
        gid=expected_gid,
        mode=0o755,
    )
    try:
        helper_stage = _stage_file(
            plan.usr_local,
            "hermes-email-boundary-verify.new",
            helper_content,
            uid=expected_uid,
            gid=expected_gid,
            mode=0o755,
        )
    except Exception:
        wrapper_stage.unlink(missing_ok=True)
        raise
    try:
        sudoers_stage = _stage_file(
            plan.sudoers_directory,
            "hermes-email-agent.new",
            rendered_sudoers.encode(),
            uid=expected_uid,
            gid=expected_gid,
            mode=0o440,
        )
    except Exception:
        wrapper_stage.unlink(missing_ok=True)
        helper_stage.unlink(missing_ok=True)
        raise
    staged = (wrapper_stage, helper_stage, sudoers_stage)
    wrapper_backup: Optional[Path] = None
    helper_backup: Optional[Path] = None
    sudoers_backup: Optional[Path] = None
    created_libexec = False
    wrapper_replaced = False
    helper_replaced = False
    sudoers_replaced = False
    try:
        validate_path(
            wrapper_stage,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            directory=False,
            exact_mode=0o755,
            acl_checker=acl_checker,
        )
        validate_path(
            helper_stage,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            directory=False,
            exact_mode=0o755,
            acl_checker=acl_checker,
        )
        validate_path(
            sudoers_stage,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            directory=False,
            exact_mode=0o440,
            acl_checker=acl_checker,
        )
        sudoers_validator(sudoers_stage)
        if plan.wrapper_destination.exists():
            wrapper_backup = _stage_file(
                plan.usr_local,
                "hermes-email-agent.backup",
                _read_source(plan.wrapper_destination),
                uid=expected_uid,
                gid=expected_gid,
                mode=0o755,
            )
        if plan.sudoers_destination.exists():
            sudoers_backup = _stage_file(
                plan.sudoers_directory,
                "hermes-email-agent.backup",
                _read_source(plan.sudoers_destination),
                uid=expected_uid,
                gid=expected_gid,
                mode=0o440,
            )
        if plan.helper_destination.exists():
            helper_backup = _stage_file(
                plan.usr_local,
                "hermes-email-boundary-verify.backup",
                _read_source(plan.helper_destination),
                uid=expected_uid,
                gid=expected_gid,
                mode=0o755,
            )
        if libexec_missing:
            plan.libexec.mkdir(mode=0o755)
            created_libexec = True
            os.chown(plan.libexec, expected_uid, expected_gid)
            os.chmod(plan.libexec, 0o755)
            validate_path(
                plan.libexec,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                directory=True,
                exact_mode=0o755,
                acl_checker=acl_checker,
            )
        replacer(wrapper_stage, plan.wrapper_destination)
        wrapper_replaced = True
        replacer(helper_stage, plan.helper_destination)
        helper_replaced = True
        replacer(sudoers_stage, plan.sudoers_destination)
        sudoers_replaced = True
        validate_path(
            plan.wrapper_destination,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            directory=False,
            exact_mode=0o755,
            acl_checker=acl_checker,
        )
        validate_path(
            plan.helper_destination,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            directory=False,
            exact_mode=0o755,
            acl_checker=acl_checker,
        )
        validate_path(
            plan.sudoers_destination,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            directory=False,
            exact_mode=0o440,
            acl_checker=acl_checker,
        )
        sudoers_validator(plan.sudoers_destination)
        if _read_source(plan.wrapper_destination) != wrapper_content:
            raise ValueError("installed wrapper bytes do not match the reviewed candidate")
        if _read_source(plan.helper_destination) != helper_content:
            raise ValueError("installed helper bytes do not match the reviewed candidate")
        if _read_source(plan.sudoers_destination) != rendered_sudoers.encode():
            raise ValueError("installed sudoers bytes do not match the reviewed policy")
    except Exception:
        wrapper_replaced = wrapper_replaced or not wrapper_stage.exists()
        helper_replaced = helper_replaced or not helper_stage.exists()
        sudoers_replaced = sudoers_replaced or not sudoers_stage.exists()
        try:
            _restore(plan.sudoers_destination, sudoers_backup, replaced=sudoers_replaced)
            _restore(plan.helper_destination, helper_backup, replaced=helper_replaced)
            _restore(plan.wrapper_destination, wrapper_backup, replaced=wrapper_replaced)
            if created_libexec:
                plan.libexec.rmdir()
        except Exception as rollback_error:
            raise RuntimeError(
                "installation failed and rollback was incomplete"
            ) from rollback_error
        raise
    finally:
        for temporary in (*staged, wrapper_backup, helper_backup, sudoers_backup):
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return actions


def main(arguments: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bridge-user", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="validate without changing files")
    mode.add_argument("--dry-run", action="store_true", help="print the validated install plan")
    args = parser.parse_args(arguments)
    try:
        uid = pwd.getpwnam("root").pw_uid
        gid = grp.getgrnam("wheel").gr_gid
        actions = install(
            build_plan(),
            args.bridge_user,
            expected_uid=uid,
            expected_gid=gid,
            mutate=not (args.check or args.dry_run),
        )
    except (KeyError, OSError, RuntimeError, ValueError) as exc:
        print(f"hermes-email-agent install failed: {exc}", file=sys.stderr)
        return 1
    if args.dry_run:
        print("\n".join(actions))
    elif args.check:
        print("preflight ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
