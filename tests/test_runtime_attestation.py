from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).parents[1]
RUNTIME_PATH = ROOT / "deploy/macos/install-hermes-email-runtime.py"
_BSD_FLAGS_ATTRIBUTE = "st_flags"
_CHFLAGS_ATTRIBUTE = "chflags"


def _runtime() -> Any:
    spec = importlib.util.spec_from_file_location("hermes_email_runtime", RUNTIME_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _no_acl(_paths: Sequence[Path]) -> None:
    pass


def _bsd_flags(path: Path) -> int:
    return cast(int, getattr(path.lstat(), _BSD_FLAGS_ATTRIBUTE))


def _set_bsd_flags(path: Path, flags: int) -> None:
    chflags = cast(Callable[..., None], getattr(os, _CHFLAGS_ATTRIBUTE))
    chflags(path, flags, follow_symlinks=False)


def _write_reviewed_build_metadata(source: Path) -> None:
    (source / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools>=77.0,<83"]\n'
        'build-backend = "setuptools.build_meta"\n'
    )


def _populate_generation(runtime: Any, paths: Any, label: str) -> None:
    python_real = paths.python_installs / "cpython-test/bin/python3.11"
    python_real.parent.mkdir(parents=True, exist_ok=True)
    python_real.write_text("reviewed python " + label + "\n")
    python_real.chmod(0o755)
    dylib = python_real.parents[1] / "lib/libpython3.11.dylib"
    dylib.parent.mkdir()
    dylib.write_text("reviewed dylib " + label + "\n")
    bin_directory = paths.venv / "bin"
    site = paths.venv / "lib/python3.11/site-packages"
    bin_directory.mkdir(parents=True, exist_ok=True)
    site.mkdir(parents=True, exist_ok=True)
    python = bin_directory / "python"
    if python.exists() or python.is_symlink():
        python.unlink()
    python.symlink_to(os.path.relpath(python_real, bin_directory))
    hermes = bin_directory / "hermes"
    active_python = paths.install_root / "runtime/venv/bin/python"
    hermes.write_text(f"#!{active_python}\nprint('stub')\n")
    hermes.chmod(0o755)
    for name in ("cli", "hermes_cli", "run_agent", "model_tools", "toolsets"):
        (site / (name + ".py")).write_text("# reviewed " + label + "\n")
    paths.artifacts.mkdir(parents=True, exist_ok=True)
    wheel = paths.artifacts / "hermes_agent-0.18.2-py3-none-any.whl"
    wheel.write_bytes(("wheel " + label + "\n").encode())
    direct = site / "hermes_agent-0.18.2.dist-info/direct_url.json"
    direct.parent.mkdir()
    direct.write_text(json.dumps(runtime.expected_direct_url(paths, active=True), sort_keys=True))
    for name in runtime.ATTESTATION_ASSETS:
        destination = paths.runtime_root / name
        shutil.copyfile(ROOT / "deploy/macos" / name, destination)
        destination.chmod(0o755 if name.endswith(".py") else 0o644)


def _fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Any, Any, Any, list[list[str]], int, int]:
    runtime = _runtime()
    paths = runtime.build_paths(tmp_path / "Hermes Runtime/hermes-agent", tmp_path / "fixed-uv")
    paths.source.mkdir(parents=True)
    _write_reviewed_build_metadata(paths.source)
    lock = paths.source / "uv.lock"
    lock.write_text("reviewed lock\n")
    monkeypatch.setattr(runtime, "LOCK_SHA256", hashlib.sha256(lock.read_bytes()).hexdigest())
    (paths.source / runtime.PROVENANCE_FILE).write_text(
        json.dumps({"source_sha256": "reviewed-source"}) + "\n"
    )
    _populate_generation(runtime, paths, "old")
    paths.uv.write_text("reviewed uv\n")
    paths.uv.chmod(0o755)
    monkeypatch.setattr(runtime, "UV_SHA256", hashlib.sha256(paths.uv.read_bytes()).hexdigest())
    uid, gid = os.getuid(), os.getgid()
    calls: list[list[str]] = []
    overrides: dict[str, Any] = {}

    def runner(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv == [str(paths.uv), "--version"]:
            return subprocess.CompletedProcess(argv, 0, runtime.UV_VERSION + "\n", "")
        if len(argv) > 1 and argv[1] == "-I":
            code_index = argv.index("-c")
            venv = Path(argv[code_index + 2])
            site = venv / "lib/python3.11/site-packages"
            evidence: dict[str, Any] = {
                "direct_url": json.loads(argv[code_index + 4]),
                "origins": {
                    name: str(site / (name + ".py"))
                    for name in ("cli", "hermes_cli", "run_agent", "model_tools", "toolsets")
                },
                "adapter_protocol": "hermes-email-bridge/1",
                "tool_schemas": 0,
                "version": runtime.VERSION,
            }
            evidence.update(overrides)
            return subprocess.CompletedProcess(argv, 0, json.dumps(evidence) + "\n", "")
        if argv[-1:] == ["--version"] and any(item.endswith("/bin/hermes") for item in argv):
            return subprocess.CompletedProcess(argv, 0, "Hermes Agent v0.18.2\n", "")
        if argv[-1:] == ["--help"] and any(item.endswith("/bin/hermes") for item in argv):
            return subprocess.CompletedProcess(argv, 0, "usage --quiet --resume --query\n", "")
        raise AssertionError(argv)

    runner.evidence = overrides  # type: ignore[attr-defined]
    runtime.normalize_tree(paths.runtime_root, uid=uid, gid=gid)
    attestation = runtime.expected_attestation(paths)
    runtime.write_attestation(paths, attestation, uid=uid, gid=gid)
    return runtime, paths, runner, calls, uid, gid


def test_attestation_verifies_actual_import_and_entrypoint_seams(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, runner, calls, uid, gid = _fixture(tmp_path, monkeypatch)
    evidence = runtime.verify_attestation(
        paths, uid=uid, gid=gid, acl_validator=_no_acl, runner=runner, probe_parent=tmp_path
    )
    assert evidence["tool_schemas"] == 0
    assert any(call[:2] == [str(paths.venv / "bin/hermes"), "--version"] for call in calls)
    assert evidence["adapter_protocol"] == "hermes-email-bridge/1"


def test_attestation_binds_build_identity_constraints_backend_and_boundary_hashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, _runner, _calls, _uid, _gid = _fixture(tmp_path, monkeypatch)
    attestation = json.loads(paths.attestation.read_text())
    assert attestation["build_account"] == "_hermesbuild"
    assert attestation["build_backend"] == {
        "artifact_sha256": runtime.BUILD_BACKEND_WHEEL_SHA256,
        "name": "setuptools.build_meta",
        "version": "81.0.0",
    }
    assert attestation["build_constraint_sha256"] == runtime.BUILD_CONSTRAINT_SHA256
    assert attestation["build_isolation"] is True
    assert attestation["build_require_hashes"] is True
    assert attestation["dependency_sync_no_build"] is True
    assert attestation["wrapper_sha256"] == runtime.WRAPPER_SHA256
    assert attestation["adapter_sha256"] == runtime.ADAPTER_SHA256
    assert attestation["adapter_protocol"] == "hermes-email-bridge/1"
    assert attestation["boundary_helper_sha256"] == runtime.BOUNDARY_HELPER_SHA256
    assert attestation["sudoers_template_sha256"] == runtime.SUDOERS_TEMPLATE_SHA256
    assert len(attestation["wheel_sha256"]) == 64


def test_offline_probe_uses_private_temp_home_and_ignores_inaccessible_service_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, valid_runner, _calls, _uid, _gid = _fixture(tmp_path, monkeypatch)
    service_home = tmp_path / "service-home"
    service_home.mkdir()
    protected = service_home / "state.txt"
    protected.write_text("unchanged\n")
    before = protected.read_bytes()
    service_home.chmod(0o000)
    probe_parent = tmp_path / "probe-homes"
    probe_parent.mkdir(mode=0o700)
    seen: list[Path] = []

    def guarded_runner(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        environment = kwargs["env"]
        home = Path(environment["HOME"])
        assert environment["HERMES_HOME"] == str(home)
        assert home != service_home
        assert home.parent == probe_parent
        assert home.stat().st_mode & 0o777 == 0o700
        assert home.stat().st_uid == os.geteuid()
        (home / "probe-state").write_text("temporary\n")
        seen.append(home)
        return cast(subprocess.CompletedProcess[str], valid_runner(argv, **kwargs))

    try:
        runtime.probe_runtime(paths, runner=guarded_runner, probe_parent=probe_parent)
        assert seen
        assert list(probe_parent.iterdir()) == []
    finally:
        service_home.chmod(0o700)
    assert protected.read_bytes() == before
    assert [path.name for path in service_home.iterdir()] == ["state.txt"]


def test_offline_probe_failure_removes_temp_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, _runner, _calls, _uid, _gid = _fixture(tmp_path, monkeypatch)
    probe_parent = tmp_path / "probe-homes"
    probe_parent.mkdir(mode=0o700)

    def failing_runner(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        home = Path(kwargs["env"]["HOME"])
        nested = home / "nested"
        nested.mkdir()
        (nested / "partial-state").write_text("must be removed\n")
        nested.chmod(0o000)
        home.chmod(0o000)
        return subprocess.CompletedProcess(argv, 1, "", "injected failure")

    with pytest.raises(ValueError, match="zero-schema probe failed"):
        runtime.probe_runtime(paths, runner=failing_runner, probe_parent=probe_parent)
    assert list(probe_parent.iterdir()) == []


def test_attestation_rejects_stale_manifest_and_tampered_dependency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, runner, _calls, uid, gid = _fixture(tmp_path, monkeypatch)
    manifest = json.loads(paths.attestation.read_text())
    manifest["lock_sha256"] = "stale"
    paths.attestation.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="stale or tampered"):
        runtime.verify_attestation(paths, uid=uid, gid=gid, acl_validator=_no_acl, runner=runner)
    runtime.write_attestation(paths, runtime.expected_attestation(paths), uid=uid, gid=gid)
    (paths.venv / "lib/python3.11/site-packages/model_tools.py").write_text("tampered\n")
    with pytest.raises(ValueError, match="stale or tampered"):
        runtime.verify_attestation(paths, uid=uid, gid=gid, acl_validator=_no_acl, runner=runner)


def test_attestation_rejects_writable_or_tampered_entrypoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, runner, _calls, uid, gid = _fixture(tmp_path, monkeypatch)
    hermes = paths.venv / "bin/hermes"
    hermes.chmod(0o777)
    with pytest.raises(ValueError, match="writable"):
        runtime.verify_attestation(paths, uid=uid, gid=gid, acl_validator=_no_acl, runner=runner)
    hermes.chmod(0o755)
    hermes.write_text("#!/bin/sh\nexit 0\n")
    runtime.write_attestation(paths, runtime.expected_attestation(paths), uid=uid, gid=gid)
    with pytest.raises(ValueError, match="shebang"):
        runtime.verify_attestation(paths, uid=uid, gid=gid, acl_validator=_no_acl, runner=runner)


@pytest.mark.parametrize("bad_direct", [{"editable": True}, {}])
def test_runtime_probe_rejects_editable_or_missing_direct_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_direct: dict[str, bool]
) -> None:
    runtime, paths, runner, _calls, _uid, _gid = _fixture(tmp_path, monkeypatch)
    runner.evidence["direct_url"] = {
        "url": paths.source.resolve().as_uri(),
        "dir_info": bad_direct,
    }
    with pytest.raises(ValueError, match="direct_url"):
        runtime.probe_runtime(paths, runner=runner, probe_parent=tmp_path)


def test_runtime_probe_rejects_import_origin_outside_venv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, runner, _calls, _uid, _gid = _fixture(tmp_path, monkeypatch)
    outside = tmp_path / "outside.py"
    outside.write_text("tampered\n")
    site = paths.venv / "lib/python3.11/site-packages"
    runner.evidence["origins"] = {
        name: str(outside if name == "model_tools" else site / (name + ".py"))
        for name in ("cli", "hermes_cli", "run_agent", "model_tools", "toolsets")
    }
    with pytest.raises(ValueError, match="import origin"):
        runtime.probe_runtime(paths, runner=runner, probe_parent=tmp_path)


def test_runtime_rejects_lock_acl_owner_and_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, runner, _calls, uid, gid = _fixture(tmp_path, monkeypatch)
    (paths.source / "uv.lock").write_text("changed\n")
    with pytest.raises(ValueError, match=r"uv\.lock"):
        runtime.verify_attestation(paths, uid=uid, gid=gid, acl_validator=_no_acl, runner=runner)
    monkeypatch.setattr(
        runtime, "LOCK_SHA256", hashlib.sha256((paths.source / "uv.lock").read_bytes()).hexdigest()
    )

    def reject_venv(paths_checked: Sequence[Path]) -> None:
        if paths.venv in paths_checked:
            raise ValueError("inherited runtime ACL")

    with pytest.raises(ValueError, match="runtime ACL"):
        runtime.validate_tree(
            paths.venv,
            expected_uid=uid,
            expected_gid=gid,
            install_root=paths.install_root,
            acl_validator=reject_venv,
        )
    with pytest.raises(ValueError, match="ownership"):
        runtime.validate_tree(
            paths.venv,
            expected_uid=uid + 1,
            expected_gid=gid,
            install_root=paths.install_root,
            acl_validator=_no_acl,
        )
    paths.venv.chmod(0o777)
    with pytest.raises(ValueError, match="writable"):
        runtime.validate_tree(
            paths.venv,
            expected_uid=uid,
            expected_gid=gid,
            install_root=paths.install_root,
            acl_validator=_no_acl,
        )


def test_runtime_rejects_symlink_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime, paths, _runner, _calls, uid, gid = _fixture(tmp_path, monkeypatch)
    escaped = paths.venv / "lib/escaped"
    escaped.symlink_to("/usr/bin/python3")
    with pytest.raises(ValueError, match="escapes"):
        runtime.validate_tree(
            paths.venv,
            expected_uid=uid,
            expected_gid=gid,
            install_root=paths.install_root,
            acl_validator=_no_acl,
        )


def test_uv_command_is_frozen_fixed_and_secret_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, _runner, _calls, _uid, _gid = _fixture(tmp_path, monkeypatch)
    command = runtime.uv_command(paths, runtime.BUILD_ACCOUNT)
    assert command[:8] == [
        "/usr/bin/sudo",
        "-n",
        "-H",
        "-u",
        "_hermesbuild",
        "/usr/bin/env",
        "-i",
        "HOME=/var/empty",
    ]
    for required in (
        "--frozen",
        "--no-dev",
        "--no-editable",
        "--no-install-project",
        "--no-build",
        "--python",
        "3.11",
    ):
        assert required in command
    build = runtime.uv_build_command(paths, runtime.BUILD_ACCOUNT)
    assert "--force-pep517" in build
    constraint_argument = build[build.index("--build-constraints") + 1]
    assert constraint_argument == runtime.PRIVATE_BUILD_CONSTRAINT
    assert not Path(constraint_argument).is_absolute()
    assert " " not in constraint_argument
    assert "--require-hashes" in build
    assert "--no-build-isolation" not in build
    assert build[build.index("--python") + 1] == "3.11"
    install = runtime.uv_install_command(
        paths, runtime.BUILD_ACCOUNT, paths.artifacts / "reviewed.whl"
    )
    assert "--no-deps" in install and "--no-build" in install
    assert "UV_PROJECT_ENVIRONMENT=" + str(paths.venv) in command
    rendered = " ".join([*command, *build, *install]).lower()
    assert "proxy" not in rendered
    assert "agentmail" not in rendered
    assert "composio" not in rendered
    assert "_hermesmail" not in rendered


@pytest.mark.parametrize(
    "mutation,error",
    [
        ("backend", "backend"),
        ("version", "constraint hash"),
        ("hash", "constraint hash"),
        ("missing", "missing"),
        ("symlink", "missing or unsafe"),
    ],
)
def test_reviewed_build_inputs_reject_unlisted_backend_and_changed_or_missing_hash(
    tmp_path: Path, mutation: str, error: str
) -> None:
    runtime = _runtime()
    source = tmp_path / "source"
    source.mkdir()
    _write_reviewed_build_metadata(source)
    constraint = tmp_path / runtime.BUILD_CONSTRAINT
    constraint.write_bytes((ROOT / "deploy/macos" / runtime.BUILD_CONSTRAINT).read_bytes())
    if mutation == "backend":
        (source / "pyproject.toml").write_text(
            '[build-system]\nrequires = ["hatchling==1.27.0"]\nbuild-backend = "hatchling.build"\n'
        )
    elif mutation == "version":
        constraint.write_text(constraint.read_text().replace("81.0.0", "80.0.0"))
    elif mutation == "hash":
        constraint.write_text(constraint.read_text().replace("fdd925", "000000"))
    elif mutation == "missing":
        constraint.unlink()
    else:
        target = tmp_path / "attacker-constraint"
        target.write_bytes(constraint.read_bytes())
        constraint.unlink()
        constraint.symlink_to(target)
    with pytest.raises(ValueError, match=error):
        runtime.verify_build_inputs(source, constraint)


def test_private_build_constraint_requires_exact_owner_mode_and_no_acl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, _runner, _calls, uid, gid = _fixture(tmp_path, monkeypatch)
    paths.build_source.mkdir(mode=0o700)
    paths.build_constraint.write_bytes(
        (ROOT / "deploy/macos" / runtime.BUILD_CONSTRAINT).read_bytes()
    )
    paths.build_constraint.chmod(0o600)
    runtime.verify_private_build_constraint(
        paths, build_uid=uid, build_gid=gid, acl_validator=_no_acl
    )
    paths.build_constraint.chmod(0o644)
    with pytest.raises(ValueError, match="mode 0600"):
        runtime.verify_private_build_constraint(
            paths, build_uid=uid, build_gid=gid, acl_validator=_no_acl
        )
    paths.build_constraint.chmod(0o600)
    with pytest.raises(ValueError, match="ownership"):
        runtime.verify_private_build_constraint(
            paths, build_uid=uid + 1, build_gid=gid, acl_validator=_no_acl
        )

    def reject(_paths: Sequence[Path]) -> None:
        raise ValueError("injected build constraint ACL")

    with pytest.raises(ValueError, match="constraint ACL"):
        runtime.verify_private_build_constraint(
            paths, build_uid=uid, build_gid=gid, acl_validator=reject
        )


def test_sdist_only_dependency_fails_closed_under_wheel_only_sync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, _runner, _calls, _uid, _gid = _fixture(tmp_path, monkeypatch)
    command = runtime.uv_command(paths, runtime.BUILD_ACCOUNT)
    assert "--no-build" in command

    def sdist_only(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert argv == command
        return subprocess.CompletedProcess(
            argv, 1, "", "no usable wheels; source distribution rejected by --no-build"
        )

    with pytest.raises(ValueError, match="generation command failed"):
        runtime._run_build_command(command, runner=sdist_only)


def test_build_account_requires_false_shell_empty_home_unique_group_and_no_supplementary_groups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime()
    builder = pwd.struct_passwd(
        ("_hermesbuild", "*", 9001, 9002, "", "/var/empty", "/usr/bin/false")
    )
    service = pwd.struct_passwd(
        ("_hermesmail", "*", 9101, 9102, "", "/var/db/hermes-email-agent", "/usr/bin/false")
    )
    groups = {
        "admin": runtime.grp.struct_group(("admin", "*", 80, [])),
        "staff": runtime.grp.struct_group(("staff", "*", 20, [])),
    }
    monkeypatch.setattr(runtime.grp, "getgrnam", groups.__getitem__)
    monkeypatch.setattr(
        runtime.grp,
        "getgrgid",
        lambda _gid: runtime.grp.struct_group(("_hermesbuild", "*", 9002, [])),
    )
    monkeypatch.setattr(runtime.grp, "getgrall", lambda: [])

    def hidden(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, "IsHidden: 1\n", "")

    runtime.verify_build_account(builder, service, runner=hidden)

    monkeypatch.setattr(
        runtime.grp,
        "getgrall",
        lambda: [runtime.grp.struct_group(("extra", "*", 9999, ["_hermesbuild"]))],
    )
    with pytest.raises(ValueError, match="supplementary"):
        runtime.verify_build_account(builder, service, runner=hidden)


@pytest.mark.skipif(
    not hasattr(os, "chflags") or not getattr(stat, "UF_IMMUTABLE", 0),
    reason="BSD immutable flags require macOS",
)
def test_disposable_source_copy_clears_uchg_without_mutating_canonical(
    tmp_path: Path,
) -> None:
    runtime = _runtime()
    source = tmp_path / "source"
    source.mkdir(mode=0o755)
    reviewed = source / "reviewed.txt"
    reviewed.write_text("reviewed canonical source\n")
    reviewed.chmod(0o644)
    flag = stat.UF_IMMUTABLE
    original_flags = {path: _bsd_flags(path) for path in (source, reviewed)}
    try:
        _set_bsd_flags(reviewed, original_flags[reviewed] | flag)
        _set_bsd_flags(source, original_flags[source] | flag)
        before_digest = runtime.filesystem_state_digest(source)
        before = {
            path: (
                path.read_bytes() if path.is_file() else None,
                stat.S_IMODE(path.lstat().st_mode),
                path.lstat().st_uid,
                path.lstat().st_gid,
                _bsd_flags(path),
            )
            for path in (source, reviewed)
        }

        disposable = tmp_path / ".build-source"
        shutil.copytree(source, disposable, symlinks=False)
        copied = disposable / reviewed.name
        assert _bsd_flags(disposable) & flag
        assert _bsd_flags(copied) & flag

        runtime.clear_disposable_flags(disposable)
        runtime.normalize_tree(disposable, uid=os.getuid(), gid=os.getgid())
        copied.write_text("build seam can mutate disposable source\n")
        (disposable / "build-output").write_text("ok\n")

        assert runtime.filesystem_state_digest(source) == before_digest
        assert {
            path: (
                path.read_bytes() if path.is_file() else None,
                stat.S_IMODE(path.lstat().st_mode),
                path.lstat().st_uid,
                path.lstat().st_gid,
                _bsd_flags(path),
            )
            for path in (source, reviewed)
        } == before
    finally:
        _set_bsd_flags(source, original_flags[source])
        _set_bsd_flags(reviewed, original_flags[reviewed])


@pytest.mark.skipif(
    not hasattr(os, "chflags") or not getattr(stat, "UF_IMMUTABLE", 0),
    reason="BSD immutable flags require macOS",
)
def test_injected_failure_cleans_flagged_disposable_generation(tmp_path: Path) -> None:
    runtime = _runtime()
    paths = runtime.build_paths(tmp_path / "hermes-agent", tmp_path / "uv")
    paths.source.mkdir(parents=True)
    _write_reviewed_build_metadata(paths.source)
    reviewed = paths.source / "uv.lock"
    reviewed.write_text("reviewed immutable source\n")
    paths.uv.write_text("reviewed uv\n")
    paths.uv.chmod(0o755)
    runtime.LOCK_SHA256 = hashlib.sha256(reviewed.read_bytes()).hexdigest()
    runtime.UV_SHA256 = hashlib.sha256(paths.uv.read_bytes()).hexdigest()
    uid, gid = os.getuid(), os.getgid()
    flag = stat.UF_IMMUTABLE
    original_flags = {path: _bsd_flags(path) for path in (paths.source, reviewed)}
    observed_build_copy = False
    try:
        _set_bsd_flags(reviewed, original_flags[reviewed] | flag)
        _set_bsd_flags(paths.source, original_flags[paths.source] | flag)
        before_digest = runtime.filesystem_state_digest(paths.source)
        before_mode = stat.S_IMODE(reviewed.lstat().st_mode)

        def runner(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            nonlocal observed_build_copy
            if argv == [str(paths.uv), "--version"]:
                return subprocess.CompletedProcess(argv, 0, runtime.UV_VERSION + "\n", "")
            if "sync" in argv:
                copied = Path(argv[argv.index("--directory") + 1])
                copied_lock = copied / "uv.lock"
                assert stat.S_IMODE(copied.parent.lstat().st_mode) == 0o711
                assert stat.S_IMODE(copied.lstat().st_mode) == 0o700
                for sibling in ("venv", "python", ".uv-cache", ".build-tmp", "artifacts"):
                    assert stat.S_IMODE((copied.parent / sibling).lstat().st_mode) == 0o700
                assert not _bsd_flags(copied) & flag
                assert not _bsd_flags(copied_lock) & flag
                copied_lock.write_text("build seam is writable\n")
                observed_build_copy = True
                _set_bsd_flags(copied_lock, _bsd_flags(copied_lock) | flag)
                _set_bsd_flags(copied, _bsd_flags(copied) | flag)
                return subprocess.CompletedProcess(argv, 1, "", "injected build failure")
            raise AssertionError(argv)

        with pytest.raises(ValueError, match="generation command failed"):
            runtime.install_runtime(
                paths,
                root_uid=uid,
                wheel_gid=gid,
                build_user=runtime.BUILD_ACCOUNT,
                build_uid=uid,
                build_gid=gid,
                runner=runner,
                acl_validator=_no_acl,
                provenance_checker=lambda: None,
                probe_parent=tmp_path,
            )
        assert observed_build_copy
        assert runtime.filesystem_state_digest(paths.source) == before_digest
        assert stat.S_IMODE(reviewed.lstat().st_mode) == before_mode
        assert _bsd_flags(reviewed) & flag
        assert _bsd_flags(paths.source) & flag
        assert not paths.runtime_root.exists()
        assert not list(paths.install_root.glob(".runtime-*"))
    finally:
        _set_bsd_flags(paths.source, original_flags[paths.source])
        _set_bsd_flags(reviewed, original_flags[reviewed])


def test_runtime_installer_cli_rejects_arbitrary_root() -> None:
    with pytest.raises(SystemExit):
        _runtime().main(["--root", "/tmp/runtime"])


@pytest.mark.skipif(
    sys.platform != "darwin" or Path("/tmp").resolve() == Path("/tmp"),
    reason="requires the macOS /tmp to /private/tmp alias",
)
def test_rebase_resolves_tmp_alias_and_final_active_verification_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime()
    root = Path(tempfile.mkdtemp(prefix="hermes-runtime-alias.", dir="/tmp"))
    install_root = root / "hermes-agent"
    stage_root = install_root / ".runtime-stage.alias"
    paths = runtime.build_paths(install_root, root / "uv", stage_root)
    uid, gid = os.getuid(), os.getgid()
    try:
        paths.source.mkdir(parents=True)
        _write_reviewed_build_metadata(paths.source)
        lock = paths.source / "uv.lock"
        lock.write_text("reviewed alias lock\n")
        monkeypatch.setattr(runtime, "LOCK_SHA256", hashlib.sha256(lock.read_bytes()).hexdigest())
        (paths.source / runtime.PROVENANCE_FILE).write_text(
            json.dumps({"source_sha256": "reviewed-alias-source"}) + "\n"
        )
        paths.uv.write_text("reviewed alias uv\n")
        os.chown(paths.uv, uid, gid)
        paths.uv.chmod(0o755)
        monkeypatch.setattr(runtime, "UV_SHA256", hashlib.sha256(paths.uv.read_bytes()).hexdigest())
        stage_root.mkdir()
        _populate_generation(runtime, paths, "alias")
        absolute_link = stage_root / "absolute-internal-python"
        absolute_link.symlink_to((paths.python_installs / "cpython-test/bin/python3.11").resolve())
        marker = stage_root / "resolved-stage-marker.txt"
        marker.write_text(str(stage_root.resolve()) + "\n")

        runtime.rebase_generation(paths)
        runtime.normalize_tree(stage_root, uid=uid, gid=gid)
        runtime.write_attestation(paths, runtime.expected_attestation(paths), uid=uid, gid=gid)
        active = runtime.build_paths(install_root, paths.uv)
        os.replace(stage_root, active.runtime_root)

        active_link = active.runtime_root / absolute_link.name
        assert not Path(os.readlink(active_link)).is_absolute()
        for path in runtime._all_paths(active.runtime_root):
            if path.is_symlink():
                assert not Path(os.readlink(path)).is_absolute()
                assert path.resolve(strict=True).is_relative_to(active.runtime_root.resolve())
                assert ".runtime-stage." not in os.readlink(path)
            elif path.is_file():
                try:
                    content = path.read_text()
                except UnicodeDecodeError:
                    continue
                assert ".runtime-stage." not in content

        def runner(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            if argv == [str(paths.uv), "--version"]:
                return subprocess.CompletedProcess(argv, 0, runtime.UV_VERSION + "\n", "")
            if len(argv) > 1 and argv[1] == "-I":
                code_index = argv.index("-c")
                venv = Path(argv[code_index + 2])
                site = venv / "lib/python3.11/site-packages"
                evidence = {
                    "direct_url": json.loads(argv[code_index + 4]),
                    "origins": {
                        name: str(site / (name + ".py"))
                        for name in (
                            "cli",
                            "hermes_cli",
                            "run_agent",
                            "model_tools",
                            "toolsets",
                        )
                    },
                    "adapter_protocol": "hermes-email-bridge/1",
                    "tool_schemas": 0,
                    "version": runtime.VERSION,
                }
                return subprocess.CompletedProcess(argv, 0, json.dumps(evidence) + "\n", "")
            if argv[-1:] == ["--version"]:
                return subprocess.CompletedProcess(argv, 0, "Hermes Agent v0.18.2\n", "")
            if argv[-1:] == ["--help"]:
                return subprocess.CompletedProcess(argv, 0, "usage --quiet --resume --query\n", "")
            raise AssertionError(argv)

        runtime.verify_attestation(
            active,
            uid=uid,
            gid=gid,
            acl_validator=_no_acl,
            runner=runner,
            probe_parent=root,
        )
    finally:
        shutil.rmtree(root)


@pytest.mark.skipif(
    sys.platform != "darwin" or os.geteuid() != 0,
    reason="requires a root-run macOS integration gate with a distinct account",
)
def test_distinct_uid_builder_traverses_non_listable_stage_only_into_private_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(tempfile.mkdtemp(prefix="hermes-runtime-distinct-uid.", dir="/private/tmp"))
    root.chmod(0o755)
    try:
        runtime, paths, runner, _calls, uid, gid = _fixture(root, monkeypatch)
        try:
            builder = pwd.getpwnam(runtime.BUILD_ACCOUNT)
            service = pwd.getpwnam("_hermesmail")
        except KeyError:
            pytest.skip("fixed _hermesbuild and _hermesmail accounts are not installed")
        runtime.verify_build_account(builder, service)
        inference_home = root / "inference-auth"
        inference_home.mkdir(mode=0o700)
        os.chown(inference_home, service.pw_uid, service.pw_gid)
        sentinel = inference_home / "auth-secret"
        sentinel.write_text("must remain unreadable\n")
        os.chown(sentinel, service.pw_uid, service.pw_gid)
        sentinel.chmod(0o600)
        observed: dict[str, Any] = {}

        def build(stage: Any, **kwargs: Any) -> None:
            details = stage.runtime_root.lstat()
            assert details.st_uid == uid
            assert details.st_gid == gid
            assert stat.S_IMODE(details.st_mode) == 0o711
            private = stage.runtime_root / "builder-private"
            sibling = stage.runtime_root / "root-private"
            private.mkdir(mode=0o700)
            os.chown(private, builder.pw_uid, builder.pw_gid)
            script = private / "run-seam"
            script.write_text('#!/bin/sh\nprintf passed > "$1"\n')
            os.chown(script, builder.pw_uid, builder.pw_gid)
            script.chmod(0o700)
            sibling.mkdir(mode=0o700)
            (sibling / "secret").write_text("root only\n")
            output = private / "result"

            executed = subprocess.run(
                ["/usr/bin/sudo", "-n", "-u", builder.pw_name, str(script), str(output)],
                capture_output=True,
                check=False,
                text=True,
            )
            listed = subprocess.run(
                ["/usr/bin/sudo", "-n", "-u", builder.pw_name, "/bin/ls", str(stage.runtime_root)],
                capture_output=True,
                check=False,
                text=True,
            )
            sibling_read = subprocess.run(
                [
                    "/usr/bin/sudo",
                    "-n",
                    "-u",
                    builder.pw_name,
                    "/bin/cat",
                    str(sibling / "secret"),
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            inference_read = subprocess.run(
                [
                    "/usr/bin/sudo",
                    "-n",
                    "-u",
                    builder.pw_name,
                    "/bin/cat",
                    str(sentinel),
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            assert executed.returncode == 0 and output.read_text() == "passed"
            assert listed.returncode != 0
            assert sibling_read.returncode != 0
            assert inference_read.returncode != 0
            observed["passed"] = True
            shutil.rmtree(private)
            shutil.rmtree(sibling)
            _populate_generation(runtime, stage, "distinct-uid")
            runtime.normalize_tree(stage.runtime_root, uid=uid, gid=gid)
            runtime.write_attestation(stage, runtime.expected_attestation(stage), uid=uid, gid=gid)

        monkeypatch.setattr(runtime, "build_generation", build)

        def final_verifier(active: Any) -> None:
            runtime.verify_attestation(
                active,
                uid=uid,
                gid=gid,
                acl_validator=_no_acl,
                runner=runner,
                probe_parent=root,
            )

        runtime.install_runtime(
            paths,
            root_uid=uid,
            wheel_gid=gid,
            build_user=builder.pw_name,
            build_uid=builder.pw_uid,
            build_gid=builder.pw_gid,
            runner=runner,
            acl_validator=_no_acl,
            provenance_checker=lambda: None,
            probe_parent=root,
            final_verifier=final_verifier,
        )
        assert observed == {"passed": True}
        assert stat.S_IMODE(paths.runtime_root.lstat().st_mode) == 0o755
        assert not list(paths.install_root.glob(".runtime-*"))
    finally:
        shutil.rmtree(root)


def _fake_generation_builder(runtime: Any, uid: int, gid: int) -> Any:
    def build(stage: Any, **kwargs: Any) -> None:
        checkpoint = kwargs["checkpoint"]
        _populate_generation(runtime, stage, "new")
        checkpoint("after_build")
        for name in runtime.ATTESTATION_ASSETS:
            checkpoint("after_asset:" + name)
        runtime.normalize_tree(stage.runtime_root, uid=uid, gid=gid)
        checkpoint("after_normalization")
        checkpoint("after_probe")
        runtime.write_attestation(stage, runtime.expected_attestation(stage), uid=uid, gid=gid)
        checkpoint("after_attestation_write")

    return build


def _install_with_fake_generation(
    runtime: Any,
    paths: Any,
    runner: Any,
    uid: int,
    gid: int,
    monkeypatch: pytest.MonkeyPatch,
    *,
    checkpoint: Any = lambda _step: None,
) -> None:
    monkeypatch.setattr(runtime, "build_generation", _fake_generation_builder(runtime, uid, gid))

    def final_verifier(active: Any) -> None:
        runtime.verify_attestation(
            active,
            uid=uid,
            gid=gid,
            acl_validator=_no_acl,
            runner=runner,
            probe_parent=paths.install_root,
        )

    runtime.install_runtime(
        paths,
        root_uid=uid,
        wheel_gid=gid,
        build_user=runtime.BUILD_ACCOUNT,
        build_uid=uid,
        build_gid=gid,
        runner=runner,
        acl_validator=_no_acl,
        provenance_checker=lambda: None,
        probe_parent=paths.install_root,
        checkpoint=checkpoint,
        final_verifier=final_verifier,
    )


PRE_COMMIT_FAULT_STEPS = [
    "after_stage_creation",
    "after_build",
    *(
        "after_asset:" + name
        for name in (
            "fetch-hermes-email-agent.py",
            "install-hermes-email-runtime.py",
            "verify-hermes-email-agent.py",
            "hermes-email-agent-adapter.py",
        )
    ),
    "after_normalization",
    "after_probe",
    "after_attestation_write",
    "after_staged_verification",
    "after_backup_rename",
    "after_activation_rename",
    "after_final_verifier",
]
POST_COMMIT_FAULT_STEPS = [
    "after_final_entrypoint",
    "backup_cleanup",
]
FAULT_STEPS = PRE_COMMIT_FAULT_STEPS + POST_COMMIT_FAULT_STEPS


@pytest.mark.parametrize("fault_step", PRE_COMMIT_FAULT_STEPS)
def test_upgrade_faults_restore_byte_identical_executable_old_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault_step: str
) -> None:
    runtime, paths, runner, _calls, uid, gid = _fixture(tmp_path, monkeypatch)
    before = runtime.filesystem_state_digest(paths.runtime_root)

    def fail(step: str) -> None:
        if step == fault_step:
            raise OSError("injected " + step)

    with pytest.raises(OSError, match="injected"):
        _install_with_fake_generation(
            runtime, paths, runner, uid, gid, monkeypatch, checkpoint=fail
        )
    assert runtime.filesystem_state_digest(paths.runtime_root) == before
    runtime.verify_attestation(
        paths,
        uid=uid,
        gid=gid,
        acl_validator=_no_acl,
        runner=runner,
        probe_parent=paths.install_root,
    )
    assert (
        "reviewed old" in (paths.venv / "lib/python3.11/site-packages/model_tools.py").read_text()
    )
    assert not list(paths.install_root.glob(".runtime-*"))


@pytest.mark.parametrize("fault_step", POST_COMMIT_FAULT_STEPS)
def test_post_commit_faults_retain_verified_new_runtime_and_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault_step: str
) -> None:
    runtime, paths, runner, _calls, uid, gid = _fixture(tmp_path, monkeypatch)
    old_inode = paths.runtime_root.stat().st_ino

    def fail(step: str) -> None:
        if step == fault_step:
            raise OSError("injected post-commit " + step)

    with pytest.raises(RuntimeError, match="activation committed; backup cleanup required"):
        _install_with_fake_generation(
            runtime, paths, runner, uid, gid, monkeypatch, checkpoint=fail
        )
    assert paths.runtime_root.stat().st_ino != old_inode
    assert (
        "reviewed new" in (paths.venv / "lib/python3.11/site-packages/model_tools.py").read_text()
    )
    runtime.verify_attestation(
        paths,
        uid=uid,
        gid=gid,
        acl_validator=_no_acl,
        runner=runner,
        probe_parent=paths.install_root,
    )
    assert len(list(paths.install_root.glob(".runtime-backup.*"))) == 1
    assert not list(paths.install_root.glob(".runtime-failed.*"))


@pytest.mark.parametrize(
    "fault_step",
    ["after_build", "after_attestation_write", "after_activation_rename"],
)
def test_failed_first_install_leaves_no_active_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault_step: str
) -> None:
    runtime, paths, runner, _calls, uid, gid = _fixture(tmp_path, monkeypatch)
    shutil.rmtree(paths.runtime_root)

    def fail(step: str) -> None:
        if step == fault_step:
            raise OSError("injected first install")

    with pytest.raises(OSError, match="injected first"):
        _install_with_fake_generation(
            runtime, paths, runner, uid, gid, monkeypatch, checkpoint=fail
        )
    assert not paths.runtime_root.exists()
    assert not list(paths.install_root.glob(".runtime-*"))


def test_post_commit_first_install_retains_verified_active_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, runner, _calls, uid, gid = _fixture(tmp_path, monkeypatch)
    shutil.rmtree(paths.runtime_root)

    def fail(step: str) -> None:
        if step == "after_final_entrypoint":
            raise OSError("injected committed first install")

    with pytest.raises(RuntimeError, match="activation committed; post-commit operation failed"):
        _install_with_fake_generation(
            runtime, paths, runner, uid, gid, monkeypatch, checkpoint=fail
        )
    assert (
        "reviewed new" in (paths.venv / "lib/python3.11/site-packages/model_tools.py").read_text()
    )
    runtime.verify_attestation(
        paths,
        uid=uid,
        gid=gid,
        acl_validator=_no_acl,
        runner=runner,
        probe_parent=paths.install_root,
    )
    assert not list(paths.install_root.glob(".runtime-*"))


def test_partial_backup_cleanup_failure_never_rolls_back_committed_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, runner, _calls, uid, gid = _fixture(tmp_path, monkeypatch)
    real_rmtree = runtime.shutil.rmtree
    committed: dict[str, Any] = {}
    removed: list[Path] = []

    def observe(step: str) -> None:
        if step == "backup_cleanup":
            committed["inode"] = paths.runtime_root.stat().st_ino
            committed["digest"] = runtime.filesystem_state_digest(paths.runtime_root)

    def partial_rmtree(path: Path, *args: Any, **kwargs: Any) -> None:
        candidate = Path(path)
        if candidate.name.startswith(".runtime-backup."):
            victim = next(item for item in runtime._all_paths(candidate) if item.is_file())
            victim.unlink()
            removed.append(victim)
            raise OSError("injected partial backup deletion")
        real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(runtime.shutil, "rmtree", partial_rmtree)
    with pytest.raises(RuntimeError, match="activation committed; backup cleanup required"):
        _install_with_fake_generation(
            runtime, paths, runner, uid, gid, monkeypatch, checkpoint=observe
        )
    assert removed and not removed[0].exists()
    assert paths.runtime_root.stat().st_ino == committed["inode"]
    assert runtime.filesystem_state_digest(paths.runtime_root) == committed["digest"]
    assert (
        "reviewed new" in (paths.venv / "lib/python3.11/site-packages/model_tools.py").read_text()
    )
    runtime.verify_attestation(
        paths,
        uid=uid,
        gid=gid,
        acl_validator=_no_acl,
        runner=runner,
        probe_parent=paths.install_root,
    )
    assert len(list(paths.install_root.glob(".runtime-backup.*"))) == 1
    assert not list(paths.install_root.glob(".runtime-failed.*"))


def test_successful_upgrade_activates_new_generation_without_debris(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, runner, _calls, uid, gid = _fixture(tmp_path, monkeypatch)
    before = runtime.filesystem_state_digest(paths.runtime_root)
    _install_with_fake_generation(runtime, paths, runner, uid, gid, monkeypatch)
    assert runtime.filesystem_state_digest(paths.runtime_root) != before
    assert (
        "reviewed new" in (paths.venv / "lib/python3.11/site-packages/model_tools.py").read_text()
    )
    runtime.verify_attestation(
        paths,
        uid=uid,
        gid=gid,
        acl_validator=_no_acl,
        runner=runner,
        probe_parent=paths.install_root,
    )
    assert json.loads(paths.attestation.read_text()) == runtime.expected_attestation(paths)
    first_inode = paths.runtime_root.stat().st_ino
    _install_with_fake_generation(runtime, paths, runner, uid, gid, monkeypatch)
    assert paths.runtime_root.stat().st_ino != first_inode
    assert json.loads(paths.attestation.read_text()) == runtime.expected_attestation(paths)
    assert not list(paths.runtime_root.rglob("*.pyc"))
    assert not list(paths.runtime_root.rglob("__pycache__"))
    assert not list(paths.install_root.glob(".runtime-*"))


@pytest.mark.skipif(
    not hasattr(os, "chflags") or not getattr(stat, "UF_IMMUTABLE", 0),
    reason="BSD immutable flags require macOS",
)
def test_flagged_backup_is_preserved_on_rollback_then_cleaned_after_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, runner, _calls, uid, gid = _fixture(tmp_path, monkeypatch)
    old_file = paths.venv / "lib/python3.11/site-packages/model_tools.py"
    original_flags = _bsd_flags(old_file)
    _set_bsd_flags(old_file, original_flags | stat.UF_IMMUTABLE)

    def fail_after_activation(step: str) -> None:
        if step == "after_activation_rename":
            raise OSError("injected activation failure")

    try:
        with pytest.raises(OSError, match="injected activation failure"):
            _install_with_fake_generation(
                runtime,
                paths,
                runner,
                uid,
                gid,
                monkeypatch,
                checkpoint=fail_after_activation,
            )
        assert _bsd_flags(old_file) & stat.UF_IMMUTABLE

        _install_with_fake_generation(runtime, paths, runner, uid, gid, monkeypatch)
        assert "reviewed new" in old_file.read_text()
        assert not _bsd_flags(old_file) & stat.UF_IMMUTABLE
        assert not list(paths.install_root.glob(".runtime-*"))
    finally:
        if old_file.exists():
            _set_bsd_flags(old_file, original_flags)
