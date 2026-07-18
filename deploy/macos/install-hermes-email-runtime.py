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
import secrets
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
ACTIVE_RUNTIME = INSTALL_ROOT / "runtime"
VENV = ACTIVE_RUNTIME / "venv"
PYTHON_INSTALLS = ACTIVE_RUNTIME / "python"
ATTESTATION = ACTIVE_RUNTIME / "runtime-attestation.json"
BOUNDARY_HELPER = Path("/usr/local/libexec/hermes-email-boundary-verify")
PROBE_PARENT = Path("/private/tmp") if Path("/private/tmp").is_dir() else Path("/tmp")
UV = Path("/usr/local/libexec/hermes-email-uv")
UV_VERSION = "uv 0.11.16 (135a36367 2026-05-21 aarch64-apple-darwin)"
UV_SHA256 = "f63ec276fa13f8f392542a334c0f58f36833b24304831e5f4c221e2edf7a16f3"
LOCK_SHA256 = "8d03d04a404c641e1c9642f0482e2d8752c57da02da94d612a5f30883b25fbca"
ARCHIVE_SHA256 = "731f785d0373c81e7fb3d18ac5f4a1b6f9d6e3b94d2ae56a5b63133045bd2c68"
COMMIT = "4281151ae859241351ba14d8c7682dc67ff4c126"
VERSION = "0.18.2"
BUILD_ACCOUNT = "_hermesbuild"
BUILD_CONSTRAINT = "hermes-email-build-constraints.txt"
PRIVATE_BUILD_CONSTRAINT = ".hermes-email-build-constraints.txt"
BUILD_CONSTRAINT_SHA256 = "a7d4688bc5ddc6d0bd3a0ee477b8f68c6bf7d4d27345cf9e54901d9e153e8f52"
BUILD_BACKEND = "setuptools.build_meta"
BUILD_BACKEND_VERSION = "81.0.0"
BUILD_BACKEND_WHEEL_SHA256 = "fdd925d5c5d9f62e4b74b30d6dd7828ce236fd6ed998a08d81de62ce5a6310d6"
WRAPPER_SHA256 = "45f98b00e022a789fe168204da220e3146699c37a6368dfdf481a5f998c8985e"
ADAPTER_SHA256 = "06f1bf892061b0beb353e5f0032169622186baff5b4ab28549cd48d64a179c3a"
SUDOERS_TEMPLATE_SHA256 = "493400bf54b26c1c988b43e0c5edcbd599d9a7a6e555e8eabdd2a25d3717da55"
BOUNDARY_HELPER_SHA256 = "4ae0a9337e0f1205c8268e82d0b5c1a4bf692ce53016fcc74b84ce1b4967f9fb"
FETCHER = Path(__file__).with_name("fetch-hermes-email-agent.py")
PROVENANCE_FILE = ".hermes-email-agent-provenance.json"
ATTESTATION_ASSETS = (
    "fetch-hermes-email-agent.py",
    "install-hermes-email-runtime.py",
    "quarantine-hermes-email-runtime-v0_3.py",
    "verify-hermes-email-agent.py",
    "hermes-email-agent-wrapper.py",
    "hermes-email-agent-adapter.py",
    "hermes-email-boundary-verify.py",
    "hermes-email-agent.sudoers",
    BUILD_CONSTRAINT,
)
BSD_MUTATION_FLAGS = sum(
    getattr(stat, name, 0) for name in ("UF_IMMUTABLE", "UF_APPEND", "SF_IMMUTABLE", "SF_APPEND")
)
STAGE_PREFIX = ".runtime-" + "stage."

Runner = Callable[..., subprocess.CompletedProcess[str]]
AclValidator = Callable[[Sequence[Path]], None]

_RUNTIME_CODE = r"""
import importlib.metadata, importlib.util, json, pathlib, runpy, sys
venv = pathlib.Path(sys.argv[1]).resolve()
source = pathlib.Path(sys.argv[2]).resolve()
expected_direct = json.loads(sys.argv[3])
adapter = pathlib.Path(sys.argv[4]).resolve()
assert sys.version_info[:2] == (3, 11)
site = pathlib.Path(importlib.metadata.distribution("hermes-agent").locate_file("")).resolve()
assert site.is_relative_to(venv)
distribution = importlib.metadata.distribution("hermes-agent")
assert distribution.version == "0.18.2"
direct = json.loads(distribution.read_text("direct_url.json"))
assert direct == expected_direct
entries = {entry.name: entry.value for entry in distribution.entry_points}
assert entries.get("hermes") == "hermes_cli.main:main"
origins = {}
for name in ("cli", "hermes_cli", "run_agent", "model_tools", "toolsets"):
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
import cli
from run_agent import AIAgent
assert callable(cli.HermesCLI) and callable(cli._finalize_single_query)
assert callable(AIAgent.run_conversation)
for method in ("_claim_active_session", "_ensure_runtime_credentials",
               "_resolve_turn_agent_config", "_init_agent"):
    assert callable(getattr(cli.HermesCLI, method, None))
adapter_ns = runpy.run_path(str(adapter))
assert adapter_ns["PROTOCOL"] == "hermes-email-bridge/2"
assert adapter_ns["HERMES_VERSION"] == "0.18.2"
assert adapter_ns["MODEL"] == "gpt-5.5"
assert adapter_ns["PROVIDER"] == "openai-codex"
assert adapter_ns["TOOLSETS"] == ["context_engine"]
assert adapter_ns["MAX_TURNS"] == 1
assert adapter_ns["NORMAL_TURN_EXIT_REASON"] == "text_response(finish_reason=stop)"
assert adapter_ns["parse_arguments"](["--query", "probe"]) == ("probe", None)
assert adapter_ns["parse_arguments"](
    ["--resume", "probe_session", "--query", "probe"]
) == ("probe", "probe_session")
print(json.dumps({"direct_url": direct, "origins": origins, "tool_schemas": 0,
                  "adapter_protocol": adapter_ns["PROTOCOL"],
                  "version": distribution.version}, sort_keys=True))
"""


@dataclass(frozen=True)
class RuntimePaths:
    install_root: Path
    runtime_root: Path
    source: Path
    venv: Path
    python_installs: Path
    attestation: Path
    uv: Path
    cache: Path
    temporary: Path
    artifacts: Path
    build_source: Path
    build_constraint: Path


def build_paths(
    install_root: Path = INSTALL_ROOT,
    uv: Path = UV,
    runtime_root: Optional[Path] = None,
) -> RuntimePaths:
    generation = install_root / "runtime" if runtime_root is None else runtime_root
    return RuntimePaths(
        install_root=install_root,
        runtime_root=generation,
        source=install_root / "source",
        venv=generation / "venv",
        python_installs=generation / "python",
        attestation=generation / "runtime-attestation.json",
        uv=uv,
        cache=generation / ".uv-cache",
        temporary=generation / ".build-tmp",
        artifacts=generation / "artifacts",
        build_source=generation / ".build-source",
        build_constraint=generation / ".build-source" / PRIVATE_BUILD_CONSTRAINT,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_regular_nofollow(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"required file is not a regular non-symlink: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


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


def clear_disposable_flags(root: Path) -> None:
    """Make a transaction-owned tree mutable without following symlinks."""
    if root.is_symlink():
        raise ValueError(f"refusing to mutate symlinked runtime path: {root}")
    if not root.exists():
        return
    for path in _all_paths(root):
        details = path.lstat()
        if path.is_symlink():
            continue
        flags = getattr(details, "st_flags", 0)
        if flags & BSD_MUTATION_FLAGS:
            os.chflags(path, flags & ~BSD_MUTATION_FLAGS, follow_symlinks=False)


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


def wheel_path(paths: RuntimePaths) -> Path:
    wheels = sorted(paths.artifacts.glob("hermes_agent-0.18.2-*.whl"))
    if len(wheels) != 1 or wheels[0].is_symlink() or not wheels[0].is_file():
        raise ValueError("runtime generation must contain exactly one Hermes wheel")
    return wheels[0]


def expected_direct_url(paths: RuntimePaths, *, active: bool) -> dict[str, Any]:
    wheel = wheel_path(paths)
    if not active:
        return {"url": wheel.as_uri(), "archive_info": {}}
    target = paths.install_root / "runtime" / "artifacts" / wheel.name
    digest = sha256_file(wheel)
    return {
        "url": target.as_uri(),
        "archive_info": {"hash": "sha256=" + digest, "hashes": {"sha256": digest}},
    }


def generation_digest(paths: RuntimePaths) -> str:
    digest = hashlib.sha256()
    for path in _all_paths(paths.runtime_root):
        if path == paths.attestation:
            continue
        details = path.lstat()
        relative = path.relative_to(paths.runtime_root).as_posix()
        kind = "L" if path.is_symlink() else "D" if path.is_dir() else "F"
        digest.update(
            f"{kind}\0{relative}\0{details.st_uid}\0{details.st_gid}\0"
            f"{stat.S_IMODE(details.st_mode):04o}\0".encode()
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


def verify_build_inputs(source: Path, constraint: Path) -> None:
    try:
        constraint_content = read_regular_nofollow(constraint)
    except OSError as exc:
        raise ValueError("reviewed build constraint is missing or unsafe") from exc
    if hashlib.sha256(constraint_content).hexdigest() != BUILD_CONSTRAINT_SHA256:
        raise ValueError("reviewed build constraint hash mismatch")
    expected_constraint = (
        f"setuptools=={BUILD_BACKEND_VERSION} \\\n    --hash=sha256:{BUILD_BACKEND_WHEEL_SHA256}\n"
    )
    try:
        decoded_constraint = constraint_content.decode()
    except UnicodeDecodeError as exc:
        raise ValueError("reviewed build constraint must be UTF-8") from exc
    if decoded_constraint != expected_constraint:
        raise ValueError("reviewed build constraint content mismatch")
    pyproject = source / "pyproject.toml"
    if pyproject.is_symlink() or not pyproject.is_file():
        raise ValueError("reviewed build metadata is missing or unsafe")
    build_block = re.search(
        r"(?ms)^\[build-system\]\s*\n"
        r'requires = \["setuptools>=77\.0,<83"\]\s*\n'
        r'build-backend = "([^"]+)"\s*$',
        pyproject.read_text(),
    )
    if build_block is None or build_block.group(1) != BUILD_BACKEND:
        raise ValueError("reviewed build backend is missing or unexpected")


def verify_private_build_constraint(
    paths: RuntimePaths,
    *,
    build_uid: int,
    build_gid: int,
    acl_validator: AclValidator,
) -> None:
    verify_build_inputs(paths.source, paths.build_constraint)
    _safe_details(
        paths.build_constraint,
        expected_uid=build_uid,
        expected_gid=build_gid,
        exact_mode=0o600,
    )
    acl_validator([paths.build_constraint])


def verify_build_account(
    builder: pwd.struct_passwd,
    service: pwd.struct_passwd,
    *,
    runner: Runner = subprocess.run,
) -> None:
    if builder.pw_name != BUILD_ACCOUNT or builder.pw_shell != "/usr/bin/false":
        raise ValueError("fixed build account name or shell is unsafe")
    if builder.pw_dir != "/var/empty" or builder.pw_uid in {0, service.pw_uid}:
        raise ValueError("fixed build account home or UID is unsafe")
    if builder.pw_gid in {
        grp.getgrnam("admin").gr_gid,
        grp.getgrnam("staff").gr_gid,
        service.pw_gid,
    }:
        raise ValueError("fixed build account group is unsafe")
    supplementary = [group.gr_name for group in grp.getgrall() if builder.pw_name in group.gr_mem]
    if supplementary:
        raise ValueError("fixed build account has supplementary group memberships")
    if grp.getgrgid(builder.pw_gid).gr_name != BUILD_ACCOUNT:
        raise ValueError("fixed build account primary group is unexpected")
    hidden = runner(
        ["/usr/bin/dscl", ".", "-read", f"/Users/{BUILD_ACCOUNT}", "IsHidden"],
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
        text=True,
        timeout=30,
    )
    if hidden.returncode != 0 or hidden.stderr or hidden.stdout.strip() != "IsHidden: 1":
        raise ValueError("fixed build account is not hidden")


def verify_service_boundary(*, runner: Runner = subprocess.run) -> dict[str, object]:
    """Require the installed root helper's recurring service-account invariants."""

    result = runner(
        [str(BOUNDARY_HELPER)],
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
        text=True,
        timeout=60,
    )
    if result.returncode != 0 or result.stderr:
        raise ValueError("dedicated service-account boundary verification failed")
    try:
        evidence = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("service-account boundary evidence is malformed") from exc
    if not isinstance(evidence, dict) or set(evidence) != {
        "accounts",
        "bridge_user",
        "sudoers_sha256",
        "wrapper_sha256",
    }:
        raise ValueError("service-account boundary evidence is incomplete")
    accounts = evidence.get("accounts")
    if not isinstance(accounts, dict) or set(accounts) != {
        "bridge_uid",
        "build_uid",
        "inference_uid",
        "inference_user",
    }:
        raise ValueError("service-account evidence has an invalid shape")
    ids = (accounts.get("bridge_uid"), accounts.get("build_uid"), accounts.get("inference_uid"))
    if (
        accounts.get("inference_user") != "_hermesmail"
        or any(not isinstance(uid, int) or isinstance(uid, bool) or uid <= 0 for uid in ids)
        or len(set(ids)) != 3
    ):
        raise ValueError("service-account evidence has invalid identities")
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n"
    if result.stdout != canonical:
        raise ValueError("service-account boundary evidence is not canonical")
    return evidence


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


def _uv_prefix(paths: RuntimePaths, build_user: str) -> list[str]:
    environment = [
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
    ]
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
    ]


def uv_command(paths: RuntimePaths, build_user: str) -> list[str]:
    return [
        *_uv_prefix(paths, build_user),
        "sync",
        "--directory",
        str(paths.build_source),
        "--frozen",
        "--no-dev",
        "--no-editable",
        "--no-install-project",
        "--no-build",
        "--python",
        "3.11",
    ]


def uv_build_command(paths: RuntimePaths, build_user: str) -> list[str]:
    return [
        *_uv_prefix(paths, build_user),
        "build",
        "--directory",
        str(paths.build_source),
        "--force-pep517",
        "--build-constraints",
        PRIVATE_BUILD_CONSTRAINT,
        "--require-hashes",
        "--python",
        "3.11",
        "--wheel",
        "--out-dir",
        str(paths.artifacts),
    ]


def uv_install_command(paths: RuntimePaths, build_user: str, wheel: Path) -> list[str]:
    return [
        *_uv_prefix(paths, build_user),
        "pip",
        "install",
        "--python",
        str(paths.venv / "bin/python"),
        "--no-deps",
        "--no-build",
        str(wheel),
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
    executable_entrypoint: bool = True,
) -> dict[str, Any]:
    python = paths.venv / "bin/python"
    hermes = paths.venv / "bin/hermes"
    adapter = paths.runtime_root / "hermes-email-agent-adapter.py"
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
    direct_urls = list(
        paths.venv.glob("lib/python*/site-packages/hermes_agent-*.dist-info/direct_url.json")
    )
    expected_direct = expected_direct_url(paths, active=executable_entrypoint)
    if len(direct_urls) != 1 or json.loads(direct_urls[0].read_text()) != expected_direct:
        raise ValueError("installed Hermes direct_url provenance is editable or unexpected")
    with temporary_probe_home(probe_parent) as home:
        environment = _runtime_environment(home)
        result = runner(
            [
                str(python),
                "-I",
                "-B",
                "-c",
                _RUNTIME_CODE,
                str(paths.venv),
                str(paths.source),
                json.dumps(
                    expected_direct_url(paths, active=executable_entrypoint), sort_keys=True
                ),
                str(adapter),
            ],
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
        if (
            evidence.get("tool_schemas") != 0
            or evidence.get("version") != VERSION
            or evidence.get("adapter_protocol") != "hermes-email-bridge/2"
        ):
            raise ValueError("installed Hermes probe returned unexpected evidence")
        if evidence.get("direct_url") != expected_direct:
            raise ValueError("installed Hermes direct_url provenance is editable or unexpected")
        origins = evidence.get("origins")
        if not isinstance(origins, dict) or set(origins) != {
            "cli",
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
        entrypoint = [str(hermes)] if executable_entrypoint else [str(python), str(hermes)]
        version = runner(
            [*entrypoint, "--version"],
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
        return evidence


def expected_attestation(paths: RuntimePaths) -> dict[str, Any]:
    provenance = json.loads((paths.source / PROVENANCE_FILE).read_text())
    python = (paths.venv / "bin/python").resolve(strict=True)
    if not python.is_relative_to(paths.python_installs.resolve()):
        raise ValueError("Hermes venv Python escapes the fixed managed-Python tree")
    hermes = paths.venv / "bin/hermes"
    active_python = (
        paths.install_root / "runtime" / python.relative_to(paths.runtime_root.resolve())
    )
    wheel = wheel_path(paths)
    constraint = paths.runtime_root / BUILD_CONSTRAINT
    verify_build_inputs(paths.source, constraint)
    wrapper_hash = sha256_file(paths.runtime_root / "hermes-email-agent-wrapper.py")
    adapter_hash = sha256_file(paths.runtime_root / "hermes-email-agent-adapter.py")
    helper_hash = sha256_file(paths.runtime_root / "hermes-email-boundary-verify.py")
    sudoers_hash = sha256_file(paths.runtime_root / "hermes-email-agent.sudoers")
    if (
        wrapper_hash != WRAPPER_SHA256
        or adapter_hash != ADAPTER_SHA256
        or helper_hash != BOUNDARY_HELPER_SHA256
        or sudoers_hash != SUDOERS_TEMPLATE_SHA256
    ):
        raise ValueError("runtime boundary candidates do not match reviewed hashes")
    return {
        "archive_sha256": ARCHIVE_SHA256,
        "adapter_protocol": "hermes-email-bridge/2",
        "adapter_sha256": adapter_hash,
        "attestation_assets": {
            name: sha256_file(paths.runtime_root / name) for name in ATTESTATION_ASSETS
        },
        "commit": COMMIT,
        "build_account": BUILD_ACCOUNT,
        "build_backend": {
            "artifact_sha256": BUILD_BACKEND_WHEEL_SHA256,
            "name": BUILD_BACKEND,
            "version": BUILD_BACKEND_VERSION,
        },
        "build_constraint_sha256": sha256_file(constraint),
        "build_isolation": True,
        "build_require_hashes": True,
        "dependency_sync_no_build": True,
        "hermes_sha256": sha256_file(hermes),
        "lock_sha256": LOCK_SHA256,
        "python_path": str(active_python),
        "python_sha256": sha256_file(python),
        "runtime_sha256": generation_digest(paths),
        "source_sha256": provenance.get("source_sha256"),
        "uv_path": str(paths.uv),
        "uv_sha256": UV_SHA256,
        "uv_version": UV_VERSION,
        "version": VERSION,
        "wrapper_sha256": wrapper_hash,
        "boundary_helper_sha256": helper_hash,
        "sudoers_template_sha256": sudoers_hash,
        "wheel": wheel.name,
        "wheel_sha256": sha256_file(wheel),
    }


def install_attestation_assets(
    source: Path,
    destination: Path,
    *,
    uid: int,
    gid: int,
    checkpoint: Callable[[str], None] = lambda _step: None,
) -> None:
    for name in ATTESTATION_ASSETS:
        content = (source / name).read_bytes()
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{name}.", dir=destination)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o755 if name.endswith(".py") else 0o644)
            os.fchown(descriptor, uid, gid)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination / name)
            checkpoint("after_asset:" + name)
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
    run_probe: bool = True,
    executable_entrypoint: bool = True,
) -> dict[str, Any]:
    verify_lock(paths.source)
    verify_uv(paths.uv, uid=uid, gid=gid, acl_validator=acl_validator, runner=runner)
    validate_tree(
        paths.runtime_root,
        expected_uid=uid,
        expected_gid=gid,
        install_root=paths.install_root,
        acl_validator=acl_validator,
    )
    _safe_details(paths.venv / "bin/python", expected_uid=uid, expected_gid=gid)
    _safe_details(paths.venv / "bin/hermes", expected_uid=uid, expected_gid=gid, exact_mode=0o755)
    _safe_details(
        paths.runtime_root / "hermes-email-agent-adapter.py",
        expected_uid=uid,
        expected_gid=gid,
        exact_mode=0o755,
    )
    _safe_details(paths.attestation, expected_uid=uid, expected_gid=gid, exact_mode=0o644)
    acl_validator([paths.attestation])
    try:
        actual = json.loads(paths.attestation.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Hermes runtime attestation is missing or malformed") from exc
    expected = expected_attestation(paths)
    if actual != expected:
        raise ValueError("Hermes runtime attestation is stale or tampered")
    if not run_probe:
        return {"tool_schemas": 0, "version": VERSION}
    evidence = probe_runtime(
        paths,
        runner=runner,
        probe_parent=probe_parent,
        executable_entrypoint=executable_entrypoint,
    )
    if json.loads(paths.attestation.read_text()) != expected_attestation(paths):
        raise ValueError("offline probe mutated the attested runtime generation")
    return evidence


def _remove_tree(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing to remove symlinked runtime path: {path}")
    if path.exists():
        clear_disposable_flags(path)
        shutil.rmtree(path)


def _remove_incomplete_runtime(paths: RuntimePaths) -> None:
    paths.attestation.unlink(missing_ok=True)
    for path in (paths.venv, paths.python_installs, paths.cache, paths.temporary):
        _remove_tree(path)


def _run_build_command(command: list[str], *, runner: Runner) -> None:
    result = runner(
        command,
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
        text=True,
        timeout=1800,
    )
    if result.returncode != 0:
        raise ValueError("frozen Hermes runtime generation command failed")


def rebase_generation(paths: RuntimePaths) -> None:
    for cache in sorted(paths.runtime_root.rglob("__pycache__"), reverse=True):
        if cache.is_dir() and not cache.is_symlink():
            shutil.rmtree(cache)
    for bytecode in paths.runtime_root.rglob("*.pyc"):
        bytecode.unlink()
    active_root = paths.install_root / "runtime"
    resolved_stage_root = paths.runtime_root.resolve()
    resolved_active_root = paths.install_root.resolve() / "runtime"
    replacements = (
        (str(paths.runtime_root), str(active_root)),
        (str(resolved_stage_root), str(resolved_active_root)),
    )
    for path in _all_paths(paths.runtime_root):
        if path.is_symlink():
            target = path.resolve(strict=True)
            if target.is_relative_to(resolved_stage_root):
                path.unlink()
                path.symlink_to(os.path.relpath(target, path.parent.resolve()))
            continue
        if not path.is_file() or path.is_relative_to(paths.artifacts):
            continue
        content = path.read_bytes()
        if not any(old.encode() in content for old, _new in replacements):
            continue
        try:
            rewritten_text = content.decode()
        except UnicodeDecodeError:
            continue
        for old, new in replacements:
            rewritten_text = rewritten_text.replace(old, new)
        path.write_bytes(rewritten_text.encode())
    direct_urls = list(
        paths.venv.glob("lib/python*/site-packages/hermes_agent-*.dist-info/direct_url.json")
    )
    if len(direct_urls) != 1:
        raise ValueError("Hermes direct_url metadata is missing from the staged runtime")
    direct_urls[0].write_text(json.dumps(expected_direct_url(paths, active=True), sort_keys=True))
    dylibs = {
        candidate.resolve(strict=True)
        for candidate in paths.python_installs.glob("cpython-*/lib/libpython3.11.dylib")
    }
    if len(dylibs) != 1:
        raise ValueError("managed Python runtime dylib is missing or unsafe")
    dylib = dylibs.pop()
    if not dylib.is_relative_to(resolved_stage_root) or not dylib.is_file():
        raise ValueError("managed Python runtime dylib escapes the staged runtime")
    if any(old.encode() in dylib.read_bytes() for old, _new in replacements):
        active_dylib = resolved_active_root / dylib.relative_to(resolved_stage_root)
        install_name = subprocess.run(
            ["/usr/bin/install_name_tool", "-id", str(active_dylib), str(dylib)],
            capture_output=True,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            text=True,
            timeout=30,
        )
        if install_name.returncode != 0 or install_name.stderr:
            raise ValueError("managed Python dylib install name could not be rebased")
        verified = subprocess.run(
            ["/usr/bin/codesign", "--verify", str(dylib)],
            capture_output=True,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            text=True,
            timeout=30,
        )
        if verified.returncode != 0 or verified.stderr:
            raise ValueError("rebased managed Python dylib signature is invalid")
    for path in _all_paths(paths.runtime_root):
        if not path.is_file() or path.is_symlink():
            continue
        content = path.read_bytes()
        if (
            any(old.encode() in content for old, _new in replacements)
            or STAGE_PREFIX.encode() in content
        ):
            raise ValueError(f"runtime generation retains staging bytes: {path}")


def build_generation(
    paths: RuntimePaths,
    *,
    asset_source: Path,
    root_uid: int,
    wheel_gid: int,
    build_user: str,
    build_uid: int,
    build_gid: int,
    runner: Runner,
    acl_validator: AclValidator,
    provenance_checker: Callable[[], None],
    probe_parent: Path,
    checkpoint: Callable[[str], None],
) -> None:
    provenance_checker()
    verify_lock(paths.source)
    verify_build_inputs(paths.source, asset_source / BUILD_CONSTRAINT)
    verify_uv(paths.uv, uid=root_uid, gid=wheel_gid, acl_validator=acl_validator, runner=runner)
    _safe_details(
        paths.runtime_root,
        expected_uid=root_uid,
        expected_gid=wheel_gid,
        exact_mode=0o711,
    )
    acl_validator([paths.runtime_root])
    for path in (paths.venv, paths.python_installs, paths.cache, paths.temporary, paths.artifacts):
        path.mkdir(mode=0o700)
        os.chown(path, build_uid, build_gid)
        os.chmod(path, 0o700)
    shutil.copytree(paths.source, paths.build_source, symlinks=False)
    clear_disposable_flags(paths.build_source)
    normalize_tree(paths.build_source, uid=build_uid, gid=build_gid)
    paths.build_source.chmod(0o700)
    shutil.copyfile(asset_source / BUILD_CONSTRAINT, paths.build_constraint)
    os.chown(paths.build_constraint, build_uid, build_gid)
    paths.build_constraint.chmod(0o600)
    verify_private_build_constraint(
        paths,
        build_uid=build_uid,
        build_gid=build_gid,
        acl_validator=acl_validator,
    )
    private_paths = [
        paths.venv,
        paths.python_installs,
        paths.cache,
        paths.temporary,
        paths.artifacts,
        paths.build_source,
    ]
    for path in private_paths:
        _safe_details(path, expected_uid=build_uid, expected_gid=build_gid, exact_mode=0o700)
    copied_paths = _all_paths(paths.build_source)
    for path in copied_paths:
        _safe_details(path, expected_uid=build_uid, expected_gid=build_gid)
    acl_validator([*private_paths[:-1], *copied_paths])
    _run_build_command(uv_command(paths, build_user), runner=runner)
    verify_private_build_constraint(
        paths,
        build_uid=build_uid,
        build_gid=build_gid,
        acl_validator=acl_validator,
    )
    _run_build_command(uv_build_command(paths, build_user), runner=runner)
    wheel = wheel_path(paths)
    _run_build_command(uv_install_command(paths, build_user, wheel), runner=runner)
    checkpoint("after_build")
    provenance_checker()
    verify_lock(paths.source)
    for path in (paths.build_source, paths.cache, paths.temporary):
        _remove_tree(path)
    install_attestation_assets(
        asset_source,
        paths.runtime_root,
        uid=root_uid,
        gid=wheel_gid,
        checkpoint=checkpoint,
    )
    normalize_tree(paths.runtime_root, uid=root_uid, gid=wheel_gid)
    validate_tree(
        paths.runtime_root,
        expected_uid=root_uid,
        expected_gid=wheel_gid,
        install_root=paths.install_root,
        acl_validator=acl_validator,
    )
    checkpoint("after_normalization")
    probe_runtime(
        paths,
        runner=runner,
        probe_parent=probe_parent,
        executable_entrypoint=False,
    )
    checkpoint("after_probe")
    rebase_generation(paths)
    normalize_tree(paths.runtime_root, uid=root_uid, gid=wheel_gid)
    write_attestation(paths, expected_attestation(paths), uid=root_uid, gid=wheel_gid)
    verify_attestation(
        paths,
        uid=root_uid,
        gid=wheel_gid,
        acl_validator=acl_validator,
        runner=runner,
        probe_parent=probe_parent,
        run_probe=False,
    )
    checkpoint("after_attestation_write")


def filesystem_state_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in _all_paths(root):
        details = path.lstat()
        relative = path.relative_to(root).as_posix()
        kind = "L" if path.is_symlink() else "D" if path.is_dir() else "F"
        digest.update(
            f"{kind}\0{relative}\0{details.st_uid}\0{details.st_gid}\0"
            f"{stat.S_IMODE(details.st_mode):04o}\0".encode()
        )
        if path.is_symlink():
            digest.update(os.readlink(path).encode())
        elif path.is_file():
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
    return digest.hexdigest()


def verify_fixed_active(paths: RuntimePaths, *, runner: Runner = subprocess.run) -> None:
    verifier = paths.runtime_root / "verify-hermes-email-agent.py"
    result = runner(
        [str(verifier)],
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
        text=True,
        timeout=300,
    )
    if result.returncode != 0 or result.stderr:
        raise ValueError("activated fixed runtime verifier failed")


def _cleanup_generation(path: Path) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise ValueError(f"runtime transaction path is unsafe: {path}")
        clear_disposable_flags(path)
        shutil.rmtree(path)


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
    asset_source: Optional[Path] = None,
    checkpoint: Callable[[str], None] = lambda _step: None,
    final_verifier: Optional[Callable[[RuntimePaths], None]] = None,
) -> None:
    active = build_paths(paths.install_root, paths.uv)
    if paths.runtime_root != active.runtime_root:
        raise ValueError("runtime installer accepts only the fixed active runtime")
    if paths.install_root == INSTALL_ROOT and build_user != BUILD_ACCOUNT:
        raise ValueError("production runtime builds require the fixed _hermesbuild account")
    verifier = (
        (lambda current: verify_fixed_active(current, runner=runner))
        if final_verifier is None
        else final_verifier
    )
    old_digest: Optional[str] = None
    if active.runtime_root.exists():
        verify_attestation(
            active,
            uid=root_uid,
            gid=wheel_gid,
            acl_validator=acl_validator,
            runner=runner,
            probe_parent=probe_parent,
        )
        old_digest = filesystem_state_digest(active.runtime_root)
    stage_root = Path(tempfile.mkdtemp(prefix=STAGE_PREFIX, dir=paths.install_root))
    stage = build_paths(paths.install_root, paths.uv, stage_root)
    backup = paths.install_root / (".runtime-backup." + secrets.token_hex(12))
    failed = paths.install_root / (".runtime-failed." + secrets.token_hex(12))
    backed_up = False
    activated = False
    committed = False
    try:
        os.chown(stage.runtime_root, root_uid, wheel_gid)
        os.chmod(stage.runtime_root, 0o711)
        _safe_details(
            stage.runtime_root,
            expected_uid=root_uid,
            expected_gid=wheel_gid,
            exact_mode=0o711,
        )
        acl_validator([stage.runtime_root])
        checkpoint("after_stage_creation")
        build_generation(
            stage,
            asset_source=Path(__file__).parent if asset_source is None else asset_source,
            root_uid=root_uid,
            wheel_gid=wheel_gid,
            build_user=build_user,
            build_uid=build_uid,
            build_gid=build_gid,
            runner=runner,
            acl_validator=acl_validator,
            provenance_checker=provenance_checker,
            probe_parent=probe_parent,
            checkpoint=checkpoint,
        )
        checkpoint("after_staged_verification")
        if active.runtime_root.exists():
            os.replace(active.runtime_root, backup)
            backed_up = True
            checkpoint("after_backup_rename")
        os.replace(stage.runtime_root, active.runtime_root)
        activated = True
        checkpoint("after_activation_rename")
        verifier(active)
        checkpoint("after_final_verifier")
        probe_runtime(active, runner=runner, probe_parent=probe_parent)
        verify_attestation(
            active,
            uid=root_uid,
            gid=wheel_gid,
            acl_validator=acl_validator,
            runner=runner,
            probe_parent=probe_parent,
            run_probe=False,
        )
        committed = True
        checkpoint("after_final_entrypoint")
        if backed_up:
            checkpoint("backup_cleanup")
            _cleanup_generation(backup)
            backed_up = False
    except Exception as original_error:
        if committed:
            if backup.exists():
                raise RuntimeError(
                    f"runtime activation committed; backup cleanup required: {backup}"
                ) from original_error
            raise RuntimeError(
                "runtime activation committed; post-commit operation failed"
            ) from original_error
        try:
            if activated and active.runtime_root.exists():
                os.replace(active.runtime_root, failed)
                activated = False
            if backed_up and backup.exists():
                os.replace(backup, active.runtime_root)
                backed_up = False
            if old_digest is None:
                if active.runtime_root.exists():
                    raise RuntimeError("failed first install left an active runtime")
            else:
                if filesystem_state_digest(active.runtime_root) != old_digest:
                    raise RuntimeError("runtime rollback did not preserve prior state")
                verify_attestation(
                    active,
                    uid=root_uid,
                    gid=wheel_gid,
                    acl_validator=acl_validator,
                    runner=runner,
                    probe_parent=probe_parent,
                )
            _cleanup_generation(failed)
            _cleanup_generation(stage.runtime_root)
        except Exception as rollback_error:
            raise RuntimeError(
                "runtime generation failed and rollback was incomplete"
            ) from rollback_error
        raise original_error
    finally:
        if stage.runtime_root.exists():
            _cleanup_generation(stage.runtime_root)
    if backup.exists() or failed.exists() or stage.runtime_root.exists():
        raise RuntimeError("runtime generation cleanup was incomplete")


def main(arguments: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify fixed prerequisites only")
    args = parser.parse_args(arguments)
    if os.geteuid() != 0:
        raise PermissionError("fixed Hermes runtime installation must run as root")
    paths = build_paths()
    uid = pwd.getpwnam("root").pw_uid
    wheel = grp.getgrnam("wheel").gr_gid
    verify_service_boundary()
    builder = pwd.getpwnam(BUILD_ACCOUNT)
    service = pwd.getpwnam("_hermesmail")
    verify_build_account(builder, service)
    verify_source_cli()
    verify_lock(paths.source)
    verify_build_inputs(paths.source, Path(__file__).with_name(BUILD_CONSTRAINT))
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
    print(paths.attestation)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, RuntimeError, ValueError) as exc:
        print(f"Hermes runtime install failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
