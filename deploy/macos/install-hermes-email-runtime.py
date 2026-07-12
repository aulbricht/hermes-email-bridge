#!/usr/bin/python3
# ruff: noqa: UP045 -- deployed system Python is macOS 3.9
"""Install and attest the fixed, frozen Hermes email-agent runtime."""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, cast

INSTALL_ROOT = Path("/Library/Application Support/HermesEmailAgent/hermes-agent")
SOURCE = INSTALL_ROOT / "source"
VENV = INSTALL_ROOT / "venv"
PYTHON_INSTALLS = INSTALL_ROOT / "python"
ATTESTATION = INSTALL_ROOT / "runtime-attestation.json"
PROBE_PARENT = Path("/private/tmp") if Path("/private/tmp").is_dir() else Path("/tmp")
UV = Path("/usr/local/libexec/hermes-email-uv")
UV_VERSION = "uv 0.11.16 (135a36367 2026-05-21 aarch64-apple-darwin)"
UV_SHA256 = "f63ec276fa13f8f392542a334c0f58f36833b24304831e5f4c221e2edf7a16f3"
LOCK_SHA256 = "8d03d04a404c641e1c9642f0482e2d8752c57da02da94d612a5f30883b25fbca"
ARCHIVE_SHA256 = "731f785d0373c81e7fb3d18ac5f4a1b6f9d6e3b94d2ae56a5b63133045bd2c68"
COMMIT = "4281151ae859241351ba14d8c7682dc67ff4c126"
VERSION = "0.18.2"
FETCHER = Path(__file__).with_name("fetch-hermes-email-agent.py")
PROVENANCE_FILE = ".hermes-email-agent-provenance.json"
ATTESTATION_ASSETS = (
    "fetch-hermes-email-agent.py",
    "install-hermes-email-runtime.py",
    "verify-hermes-email-agent.py",
)

Runner = Callable[..., subprocess.CompletedProcess[str]]
AclValidator = Callable[[Sequence[Path]], None]

_RUNTIME_CODE = r"""
import importlib.metadata, importlib.util, json, pathlib, sys
venv = pathlib.Path(sys.argv[1]).resolve()
source = pathlib.Path(sys.argv[2]).resolve()
assert sys.version_info[:2] == (3, 11)
site = pathlib.Path(importlib.metadata.distribution("hermes-agent").locate_file("")).resolve()
assert site.is_relative_to(venv)
distribution = importlib.metadata.distribution("hermes-agent")
assert distribution.version == "0.18.2"
direct = json.loads(distribution.read_text("direct_url.json"))
assert direct == {"url": source.as_uri(), "dir_info": {"editable": False}}
entries = {entry.name: entry.value for entry in distribution.entry_points}
assert entries.get("hermes") == "hermes_cli.main:main"
origins = {}
for name in ("hermes_cli", "run_agent", "model_tools", "toolsets"):
    spec = importlib.util.find_spec(name)
    assert spec is not None and spec.origin is not None
    origin = pathlib.Path(spec.origin).resolve()
    assert origin.is_relative_to(site) and not origin.is_relative_to(source)
    origins[name] = str(origin)
import toolsets
assert toolsets.validate_toolset("context_engine") is True
assert toolsets.resolve_toolset("context_engine") == []
from model_tools import get_tool_definitions
definitions = get_tool_definitions(enabled_toolsets=["context_engine"], quiet_mode=True)
assert definitions == []
print(json.dumps({"direct_url": direct, "origins": origins, "tool_schemas": 0,
                  "version": distribution.version}, sort_keys=True))
"""


@dataclass(frozen=True)
class RuntimePaths:
    install_root: Path
    source: Path
    venv: Path
    python_installs: Path
    attestation: Path
    uv: Path
    cache: Path
    temporary: Path


def build_paths(install_root: Path = INSTALL_ROOT, uv: Path = UV) -> RuntimePaths:
    return RuntimePaths(
        install_root=install_root,
        source=install_root / "source",
        venv=install_root / "venv",
        python_installs=install_root / "python",
        attestation=install_root / "runtime-attestation.json",
        uv=uv,
        cache=install_root / ".uv-cache",
        temporary=install_root / ".build-tmp",
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _all_paths(root: Path) -> list[Path]:
    paths = [root]
    for directory, names, files in os.walk(root, followlinks=False):
        base = Path(directory)
        paths.extend(base / name for name in sorted(names))
        paths.extend(base / name for name in sorted(files))
    return sorted(set(paths))


def _safe_details(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    exact_mode: Optional[int] = None,
) -> os.stat_result:
    details = path.lstat()
    if not (stat.S_ISDIR(details.st_mode) or stat.S_ISREG(details.st_mode) or path.is_symlink()):
        raise ValueError(f"runtime path has an unsafe type: {path}")
    if details.st_uid != expected_uid or details.st_gid != expected_gid:
        raise ValueError(f"runtime path has unsafe ownership: {path}")
    mode = stat.S_IMODE(details.st_mode)
    if exact_mode is not None and mode != exact_mode:
        raise ValueError(f"runtime path must have mode {exact_mode:04o}: {path}")
    if not path.is_symlink() and mode & 0o022:
        raise ValueError(f"runtime path cannot be group/other writable: {path}")
    return details


def reject_acls(paths: Sequence[Path]) -> None:
    for offset in range(0, len(paths), 500):
        result = subprocess.run(
            ["/bin/ls", "-lde", *(str(path) for path in paths[offset : offset + 500])],
            capture_output=True,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError("cannot inspect Hermes runtime ACLs")
        if any(
            (line.split() and line.split()[0].endswith("+"))
            or re.match(r"\s+\d+:", line) is not None
            for line in result.stdout.splitlines()
        ):
            raise ValueError("Hermes runtime contains an unexpected ACL")


def _validate_symlinks(paths: Sequence[Path], install_root: Path) -> None:
    trusted = install_root.resolve()
    for path in paths:
        if not path.is_symlink():
            continue
        try:
            target = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"runtime contains a broken or cyclic symlink: {path}") from exc
        if not target.is_relative_to(trusted):
            raise ValueError(f"runtime symlink escapes the fixed root: {path}")


def validate_tree(
    root: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    install_root: Path,
    acl_validator: AclValidator = reject_acls,
) -> list[Path]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"runtime tree must be a non-symlink directory: {root}")
    paths = _all_paths(root)
    for path in paths:
        _safe_details(path, expected_uid=expected_uid, expected_gid=expected_gid)
    _validate_symlinks(paths, install_root)
    acl_validator(paths)
    return paths


def normalize_tree(root: Path, *, uid: int, gid: int) -> None:
    for path in reversed(_all_paths(root)):
        os.chown(path, uid, gid, follow_symlinks=False)
        if path.is_symlink():
            continue
        mode = stat.S_IMODE(path.lstat().st_mode)
        os.chmod(path, 0o755 if path.is_dir() or mode & 0o111 else 0o644)


def tree_digest(roots: Sequence[Path]) -> str:
    digest = hashlib.sha256()
    for root in roots:
        for path in _all_paths(root):
            details = path.lstat()
            relative = path.relative_to(root).as_posix()
            kind = "L" if path.is_symlink() else "D" if path.is_dir() else "F"
            digest.update(
                f"{root.name}\0{kind}\0{relative}\0{stat.S_IMODE(details.st_mode):04o}\0".encode()
            )
            if path.is_symlink():
                digest.update(os.readlink(path).encode())
            elif path.is_file():
                with path.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
    return digest.hexdigest()


def verify_source_cli(*, runner: Runner = subprocess.run) -> None:
    result = runner(
        ["/usr/bin/python3", str(FETCHER), "--verify"],
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
        text=True,
        timeout=120,
    )
    if result.returncode != 0 or result.stderr:
        raise ValueError("fixed Hermes source provenance verification failed")


def verify_lock(source: Path) -> None:
    lock = source / "uv.lock"
    if lock.is_symlink() or not lock.is_file() or sha256_file(lock) != LOCK_SHA256:
        raise ValueError("Hermes uv.lock does not match the reviewed lock")


def verify_uv(
    uv: Path,
    *,
    uid: int,
    gid: int,
    acl_validator: AclValidator = reject_acls,
    runner: Runner = subprocess.run,
) -> None:
    if uv == UV:
        verify_usr_local_chain(uv, uid=uid, gid=gid, acl_validator=acl_validator)
    _safe_details(uv, expected_uid=uid, expected_gid=gid, exact_mode=0o755)
    acl_validator([uv])
    if sha256_file(uv) != UV_SHA256:
        raise ValueError("fixed uv binary SHA-256 mismatch")
    result = runner(
        [str(uv), "--version"],
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        text=True,
        timeout=30,
    )
    if result.returncode != 0 or result.stderr or result.stdout.strip() != UV_VERSION:
        raise ValueError("fixed uv binary version mismatch")


def verify_usr_local_chain(
    executable: Path,
    *,
    uid: int,
    gid: int,
    acl_validator: AclValidator = reject_acls,
) -> None:
    expected_parent = Path("/usr/local/libexec")
    if executable.parent != expected_parent:
        raise ValueError("fixed executable is outside /usr/local/libexec")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptors: list[int] = []
    try:
        descriptor = os.open("/", flags)
        descriptors.append(descriptor)
        paths = [Path("/"), Path("/usr"), Path("/usr/local"), expected_parent]
        _safe_details(paths[0], expected_uid=uid, expected_gid=gid, exact_mode=0o755)
        for name, path in zip(  # noqa: B905 -- deployed Python 3.9 has no strict=
            ("usr", "local", "libexec"), paths[1:]
        ):
            details = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(details.st_mode):
                raise ValueError(f"fixed executable chain is not a directory: {path}")
            _safe_details(path, expected_uid=uid, expected_gid=gid, exact_mode=0o755)
            descriptor = os.open(name, flags, dir_fd=descriptor)
            descriptors.append(descriptor)
        acl_validator(paths)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def uv_command(paths: RuntimePaths, build_user: str) -> list[str]:
    environment = (
        "HOME=/var/empty",
        "LANG=C",
        "PATH=/usr/bin:/bin",
        "TMPDIR=" + str(paths.temporary),
        "UV_CACHE_DIR=" + str(paths.cache),
        "UV_NO_CONFIG=1",
        "UV_NO_PROGRESS=1",
        "UV_PROJECT_ENVIRONMENT=" + str(paths.venv),
        "UV_PYTHON_INSTALL_DIR=" + str(paths.python_installs),
        "UV_PYTHON_PREFERENCE=managed",
    )
    return [
        "/usr/bin/sudo",
        "-n",
        "-H",
        "-u",
        build_user,
        "/usr/bin/env",
        "-i",
        *environment,
        str(paths.uv),
        "sync",
        "--directory",
        str(paths.source),
        "--frozen",
        "--no-dev",
        "--no-editable",
        "--python",
        "3.11",
    ]


def _runtime_environment(home: Path) -> dict[str, str]:
    return {
        "HOME": str(home),
        "HERMES_HOME": str(home),
        "LANG": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


@contextmanager
def temporary_probe_home(parent: Path = PROBE_PARENT) -> Iterator[Path]:
    home = Path(tempfile.mkdtemp(prefix="hermes-email-runtime-probe.", dir=parent))
    try:
        home.chmod(0o700)
        details = home.lstat()
        if home.is_symlink() or not home.is_dir():
            raise ValueError("offline probe home is not a private directory")
        if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o700:
            raise ValueError("offline probe home has unsafe ownership or mode")
        yield home
    finally:
        if home.is_symlink():
            home.unlink()
        elif home.exists():
            home.chmod(0o700)
            for directory, names, _files in os.walk(home):
                for name in names:
                    child = Path(directory) / name
                    if child.is_dir() and not child.is_symlink():
                        child.chmod(0o700)
            shutil.rmtree(home)


def probe_runtime(
    paths: RuntimePaths,
    *,
    runner: Runner = subprocess.run,
    probe_parent: Path = PROBE_PARENT,
) -> dict[str, Any]:
    python = paths.venv / "bin/python"
    hermes = paths.venv / "bin/hermes"
    expected_shebang = "#!" + str(python)
    if hermes.is_symlink() or not hermes.is_file():
        raise ValueError("Hermes console entrypoint is missing or unsafe")
    entrypoint_lines = hermes.read_text(errors="replace").splitlines()
    direct_shebang = entrypoint_lines[:1] == [expected_shebang]
    shell_trampoline = (
        len(entrypoint_lines) >= 3
        and entrypoint_lines[0] == "#!/bin/sh"
        and entrypoint_lines[1] == f"'''exec' '{python}' \"$0\" \"$@\""
        and entrypoint_lines[2] == "' '''"
    )
    if not (direct_shebang or shell_trampoline):
        raise ValueError("Hermes console entrypoint shebang is not fixed to the runtime")
    with temporary_probe_home(probe_parent) as home:
        environment = _runtime_environment(home)
        result = runner(
            [str(python), "-I", "-c", _RUNTIME_CODE, str(paths.venv), str(paths.source)],
            capture_output=True,
            check=False,
            env=environment,
            text=True,
            timeout=120,
        )
        if result.returncode != 0 or result.stderr:
            raise ValueError("installed Hermes import and zero-schema probe failed")
        try:
            evidence = cast(dict[str, Any], json.loads(result.stdout))
        except json.JSONDecodeError as exc:
            raise ValueError("installed Hermes probe returned malformed evidence") from exc
        if evidence.get("tool_schemas") != 0 or evidence.get("version") != VERSION:
            raise ValueError("installed Hermes probe returned unexpected evidence")
        expected_direct = {
            "url": paths.source.resolve().as_uri(),
            "dir_info": {"editable": False},
        }
        if evidence.get("direct_url") != expected_direct:
            raise ValueError("installed Hermes direct_url provenance is editable or unexpected")
        origins = evidence.get("origins")
        if not isinstance(origins, dict) or set(origins) != {
            "hermes_cli",
            "run_agent",
            "model_tools",
            "toolsets",
        }:
            raise ValueError("installed Hermes import-origin evidence is incomplete")
        for value in origins.values():
            if not isinstance(value, str):
                raise ValueError("installed Hermes import-origin evidence is malformed")
            origin = Path(value).resolve()
            if not origin.is_file() or not origin.is_relative_to(paths.venv.resolve()):
                raise ValueError("installed Hermes import origin escapes the fixed runtime")
        version = runner(
            [str(hermes), "--version"],
            capture_output=True,
            check=False,
            env=environment,
            text=True,
            timeout=60,
        )
        if (
            version.returncode != 0
            or version.stderr
            or not version.stdout.startswith("Hermes Agent v0.18.2")
        ):
            raise ValueError("installed Hermes console version contract failed")
        base = [
            str(hermes),
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
        ]
        for suffix in (
            ["--query", "probe", "--help"],
            ["--resume", "probe_session", "--query", "probe", "--help"],
        ):
            parsed = runner(
                [*base, *suffix],
                capture_output=True,
                check=False,
                env=environment,
                text=True,
                timeout=60,
            )
            if parsed.returncode != 0 or parsed.stderr or "--quiet" not in parsed.stdout:
                raise ValueError("installed Hermes console parser contract failed")
        return evidence


def expected_attestation(paths: RuntimePaths) -> dict[str, Any]:
    provenance = json.loads((paths.source / PROVENANCE_FILE).read_text())
    python = (paths.venv / "bin/python").resolve(strict=True)
    if not python.is_relative_to(paths.python_installs.resolve()):
        raise ValueError("Hermes venv Python escapes the fixed managed-Python tree")
    hermes = paths.venv / "bin/hermes"
    return {
        "archive_sha256": ARCHIVE_SHA256,
        "attestation_assets": {
            name: sha256_file(Path(__file__).parent / name) for name in ATTESTATION_ASSETS
        },
        "commit": COMMIT,
        "hermes_sha256": sha256_file(hermes),
        "lock_sha256": LOCK_SHA256,
        "python_path": str(python),
        "python_sha256": sha256_file(python),
        "runtime_sha256": tree_digest([paths.python_installs, paths.venv]),
        "source_sha256": provenance.get("source_sha256"),
        "uv_path": str(paths.uv),
        "uv_sha256": UV_SHA256,
        "uv_version": UV_VERSION,
        "version": VERSION,
    }


def install_attestation_assets(source: Path, destination: Path, *, uid: int, gid: int) -> None:
    for name in ATTESTATION_ASSETS:
        content = (source / name).read_bytes()
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{name}.", dir=destination)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o755)
            os.fchown(descriptor, uid, gid)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination / name)
        finally:
            temporary.unlink(missing_ok=True)


def write_attestation(
    paths: RuntimePaths, attestation: dict[str, Any], *, uid: int, gid: int
) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".runtime-attestation.", dir=paths.install_root
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(attestation, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, paths.attestation)
    finally:
        temporary.unlink(missing_ok=True)


def verify_attestation(
    paths: RuntimePaths,
    *,
    uid: int,
    gid: int,
    acl_validator: AclValidator = reject_acls,
    runner: Runner = subprocess.run,
    probe_parent: Path = PROBE_PARENT,
) -> dict[str, Any]:
    verify_lock(paths.source)
    verify_uv(paths.uv, uid=uid, gid=gid, acl_validator=acl_validator, runner=runner)
    for root in (paths.python_installs, paths.venv):
        validate_tree(
            root,
            expected_uid=uid,
            expected_gid=gid,
            install_root=paths.install_root,
            acl_validator=acl_validator,
        )
    _safe_details(paths.venv / "bin/python", expected_uid=uid, expected_gid=gid)
    _safe_details(paths.venv / "bin/hermes", expected_uid=uid, expected_gid=gid, exact_mode=0o755)
    _safe_details(paths.attestation, expected_uid=uid, expected_gid=gid, exact_mode=0o644)
    acl_validator([paths.attestation])
    try:
        actual = json.loads(paths.attestation.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Hermes runtime attestation is missing or malformed") from exc
    expected = expected_attestation(paths)
    if actual != expected:
        raise ValueError("Hermes runtime attestation is stale or tampered")
    return probe_runtime(paths, runner=runner, probe_parent=probe_parent)


def _remove_tree(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing to remove symlinked runtime path: {path}")
    if path.exists():
        shutil.rmtree(path)


def _remove_incomplete_runtime(paths: RuntimePaths) -> None:
    paths.attestation.unlink(missing_ok=True)
    for path in (paths.venv, paths.python_installs, paths.cache, paths.temporary):
        _remove_tree(path)


def install_runtime(
    paths: RuntimePaths,
    *,
    root_uid: int,
    wheel_gid: int,
    build_user: str,
    build_uid: int,
    build_gid: int,
    runner: Runner = subprocess.run,
    acl_validator: AclValidator = reject_acls,
    provenance_checker: Callable[[], None] = verify_source_cli,
    probe_parent: Path = PROBE_PARENT,
) -> None:
    provenance_checker()
    verify_lock(paths.source)
    verify_uv(paths.uv, uid=root_uid, gid=wheel_gid, acl_validator=acl_validator, runner=runner)
    paths.attestation.unlink(missing_ok=True)
    for path in (paths.venv, paths.python_installs, paths.cache, paths.temporary):
        _remove_tree(path)
        path.mkdir(mode=0o700)
        os.chown(path, build_uid, build_gid)
        os.chmod(path, 0o700)
    try:
        result = runner(
            uv_command(paths, build_user),
            capture_output=True,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
            text=True,
            timeout=1800,
        )
        if result.returncode != 0:
            raise ValueError("frozen Hermes runtime installation failed")
        provenance_checker()
        verify_lock(paths.source)
        for path in (paths.cache, paths.temporary):
            _remove_tree(path)
        for root in (paths.python_installs, paths.venv):
            normalize_tree(root, uid=root_uid, gid=wheel_gid)
            validate_tree(
                root,
                expected_uid=root_uid,
                expected_gid=wheel_gid,
                install_root=paths.install_root,
                acl_validator=acl_validator,
            )
        probe_runtime(paths, runner=runner, probe_parent=probe_parent)
        write_attestation(paths, expected_attestation(paths), uid=root_uid, gid=wheel_gid)
        verify_attestation(
            paths,
            uid=root_uid,
            gid=wheel_gid,
            acl_validator=acl_validator,
            runner=runner,
            probe_parent=probe_parent,
        )
    except Exception:
        _remove_incomplete_runtime(paths)
        raise


def main(arguments: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify fixed prerequisites only")
    args = parser.parse_args(arguments)
    if os.geteuid() != 0:
        raise PermissionError("fixed Hermes runtime installation must run as root")
    paths = build_paths()
    uid = pwd.getpwnam("root").pw_uid
    wheel = grp.getgrnam("wheel").gr_gid
    builder = pwd.getpwnam("_hermesmail")
    verify_source_cli()
    verify_lock(paths.source)
    verify_uv(paths.uv, uid=uid, gid=wheel)
    if args.check:
        print("fixed runtime prerequisites verified")
        return 0
    install_runtime(
        paths,
        root_uid=uid,
        wheel_gid=wheel,
        build_user=builder.pw_name,
        build_uid=builder.pw_uid,
        build_gid=builder.pw_gid,
    )
    install_attestation_assets(Path(__file__).parent, UV.parent, uid=uid, gid=wheel)
    print(paths.attestation)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, RuntimeError, ValueError) as exc:
        print(f"Hermes runtime install failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
