from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).parents[1]
RUNTIME_PATH = ROOT / "deploy/macos/install-hermes-email-runtime.py"


def _runtime() -> Any:
    spec = importlib.util.spec_from_file_location("hermes_email_runtime", RUNTIME_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _no_acl(_paths: Sequence[Path]) -> None:
    pass


def _populate_generation(runtime: Any, paths: Any, label: str) -> None:
    python_real = paths.python_installs / "cpython/bin/python3.11"
    python_real.parent.mkdir(parents=True, exist_ok=True)
    python_real.write_text("reviewed python " + label + "\n")
    python_real.chmod(0o755)
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
    for name in ("hermes_cli", "run_agent", "model_tools", "toolsets"):
        (site / (name + ".py")).write_text("# reviewed " + label + "\n")
    paths.artifacts.mkdir(parents=True, exist_ok=True)
    wheel = paths.artifacts / "hermes_agent-0.18.2-py3-none-any.whl"
    wheel.write_bytes(("wheel " + label + "\n").encode())
    direct = site / "hermes_agent-0.18.2.dist-info/direct_url.json"
    direct.parent.mkdir()
    direct.write_text(json.dumps(runtime.expected_direct_url(paths, active=True), sort_keys=True))
    for name in runtime.ATTESTATION_ASSETS:
        shutil.copyfile(ROOT / "deploy/macos" / name, paths.runtime_root / name)


def _fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Any, Any, Any, list[list[str]], int, int]:
    runtime = _runtime()
    paths = runtime.build_paths(tmp_path / "Hermes Runtime/hermes-agent", tmp_path / "fixed-uv")
    paths.source.mkdir(parents=True)
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
                    for name in ("hermes_cli", "run_agent", "model_tools", "toolsets")
                },
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
    parser_calls = [call for call in calls if call[-1:] == ["--help"]]
    assert len(parser_calls) == 2
    assert "--resume" not in parser_calls[0]
    resume_index = parser_calls[1].index("--resume")
    assert parser_calls[1][resume_index : resume_index + 2] == ["--resume", "probe_session"]


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
        for name in ("hermes_cli", "run_agent", "model_tools", "toolsets")
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
    command = runtime.uv_command(paths, "_hermesmail")
    assert command[:8] == [
        "/usr/bin/sudo",
        "-n",
        "-H",
        "-u",
        "_hermesmail",
        "/usr/bin/env",
        "-i",
        "HOME=/var/empty",
    ]
    assert command[-6:] == [
        "--frozen",
        "--no-dev",
        "--no-editable",
        "--no-install-project",
        "--python",
        "3.11",
    ]
    assert "UV_PROJECT_ENVIRONMENT=" + str(paths.venv) in command
    rendered = " ".join(command).lower()
    assert "proxy" not in rendered
    assert "agentmail" not in rendered
    assert "composio" not in rendered


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
    original_flags = {path: path.lstat().st_flags for path in (source, reviewed)}
    try:
        os.chflags(reviewed, original_flags[reviewed] | flag, follow_symlinks=False)
        os.chflags(source, original_flags[source] | flag, follow_symlinks=False)
        before_digest = runtime.filesystem_state_digest(source)
        before = {
            path: (
                path.read_bytes() if path.is_file() else None,
                stat.S_IMODE(path.lstat().st_mode),
                path.lstat().st_uid,
                path.lstat().st_gid,
                path.lstat().st_flags,
            )
            for path in (source, reviewed)
        }

        disposable = tmp_path / ".build-source"
        shutil.copytree(source, disposable, symlinks=False)
        copied = disposable / reviewed.name
        assert disposable.lstat().st_flags & flag
        assert copied.lstat().st_flags & flag

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
                path.lstat().st_flags,
            )
            for path in (source, reviewed)
        } == before
    finally:
        os.chflags(source, original_flags[source], follow_symlinks=False)
        os.chflags(reviewed, original_flags[reviewed], follow_symlinks=False)


@pytest.mark.skipif(
    not hasattr(os, "chflags") or not getattr(stat, "UF_IMMUTABLE", 0),
    reason="BSD immutable flags require macOS",
)
def test_injected_failure_cleans_flagged_disposable_generation(tmp_path: Path) -> None:
    runtime = _runtime()
    paths = runtime.build_paths(tmp_path / "hermes-agent", tmp_path / "uv")
    paths.source.mkdir(parents=True)
    reviewed = paths.source / "uv.lock"
    reviewed.write_text("reviewed immutable source\n")
    paths.uv.write_text("reviewed uv\n")
    paths.uv.chmod(0o755)
    runtime.LOCK_SHA256 = hashlib.sha256(reviewed.read_bytes()).hexdigest()
    runtime.UV_SHA256 = hashlib.sha256(paths.uv.read_bytes()).hexdigest()
    uid, gid = os.getuid(), os.getgid()
    flag = stat.UF_IMMUTABLE
    original_flags = {path: path.lstat().st_flags for path in (paths.source, reviewed)}
    observed_build_copy = False
    try:
        os.chflags(reviewed, original_flags[reviewed] | flag, follow_symlinks=False)
        os.chflags(paths.source, original_flags[paths.source] | flag, follow_symlinks=False)
        before_digest = runtime.filesystem_state_digest(paths.source)
        before_mode = stat.S_IMODE(reviewed.lstat().st_mode)

        def runner(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            nonlocal observed_build_copy
            if argv == [str(paths.uv), "--version"]:
                return subprocess.CompletedProcess(argv, 0, runtime.UV_VERSION + "\n", "")
            if "sync" in argv:
                copied = Path(argv[argv.index("--directory") + 1])
                copied_lock = copied / "uv.lock"
                assert not copied.lstat().st_flags & flag
                assert not copied_lock.lstat().st_flags & flag
                copied_lock.write_text("build seam is writable\n")
                observed_build_copy = True
                os.chflags(
                    copied_lock,
                    copied_lock.lstat().st_flags | flag,
                    follow_symlinks=False,
                )
                os.chflags(copied, copied.lstat().st_flags | flag, follow_symlinks=False)
                return subprocess.CompletedProcess(argv, 1, "", "injected build failure")
            raise AssertionError(argv)

        with pytest.raises(ValueError, match="generation command failed"):
            runtime.install_runtime(
                paths,
                root_uid=uid,
                wheel_gid=gid,
                build_user="_hermesmail",
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
        assert reviewed.lstat().st_flags & flag
        assert paths.source.lstat().st_flags & flag
        assert not paths.runtime_root.exists()
        assert not list(paths.install_root.glob(".runtime-*"))
    finally:
        os.chflags(paths.source, original_flags[paths.source], follow_symlinks=False)
        os.chflags(reviewed, original_flags[reviewed], follow_symlinks=False)


def test_runtime_installer_cli_rejects_arbitrary_root() -> None:
    with pytest.raises(SystemExit):
        _runtime().main(["--root", "/tmp/runtime"])


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
        build_user="_hermesmail",
        build_uid=uid,
        build_gid=gid,
        runner=runner,
        acl_validator=_no_acl,
        provenance_checker=lambda: None,
        probe_parent=paths.install_root,
        checkpoint=checkpoint,
        final_verifier=final_verifier,
    )


FAULT_STEPS = [
    "after_stage_creation",
    "after_build",
    *(
        "after_asset:" + name
        for name in (
            "fetch-hermes-email-agent.py",
            "install-hermes-email-runtime.py",
            "verify-hermes-email-agent.py",
        )
    ),
    "after_normalization",
    "after_probe",
    "after_attestation_write",
    "after_staged_verification",
    "after_backup_rename",
    "after_activation_rename",
    "after_final_verifier",
    "after_final_entrypoint",
    "backup_cleanup",
]


@pytest.mark.parametrize("fault_step", FAULT_STEPS)
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


@pytest.mark.parametrize(
    "fault_step",
    ["after_build", "after_attestation_write", "after_activation_rename", "after_final_entrypoint"],
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
    original_flags = old_file.lstat().st_flags
    os.chflags(old_file, original_flags | stat.UF_IMMUTABLE, follow_symlinks=False)

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
        assert old_file.lstat().st_flags & stat.UF_IMMUTABLE

        _install_with_fake_generation(runtime, paths, runner, uid, gid, monkeypatch)
        assert "reviewed new" in old_file.read_text()
        assert not old_file.lstat().st_flags & stat.UF_IMMUTABLE
        assert not list(paths.install_root.glob(".runtime-*"))
    finally:
        if old_file.exists():
            os.chflags(old_file, original_flags, follow_symlinks=False)
