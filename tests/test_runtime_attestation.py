from __future__ import annotations

import hashlib
import importlib.util
import json
import os
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
    python_real = paths.python_installs / "cpython/bin/python3.11"
    python_real.parent.mkdir(parents=True)
    python_real.write_text("reviewed python\n")
    python_real.chmod(0o755)
    bin_directory = paths.venv / "bin"
    site = paths.venv / "lib/python3.11/site-packages"
    bin_directory.mkdir(parents=True)
    site.mkdir(parents=True)
    (bin_directory / "python").symlink_to(python_real)
    hermes = bin_directory / "hermes"
    hermes.write_text(f"#!{bin_directory / 'python'}\nprint('stub')\n")
    hermes.chmod(0o755)
    origins: dict[str, str] = {}
    for name in ("hermes_cli", "run_agent", "model_tools", "toolsets"):
        path = site / (name + ".py")
        path.write_text("# reviewed\n")
        origins[name] = str(path)
    paths.uv.write_text("reviewed uv\n")
    paths.uv.chmod(0o755)
    monkeypatch.setattr(runtime, "UV_SHA256", hashlib.sha256(paths.uv.read_bytes()).hexdigest())
    uid, gid = os.getuid(), os.getgid()
    calls: list[list[str]] = []
    evidence: dict[str, Any] = {
        "direct_url": {"url": paths.source.resolve().as_uri(), "dir_info": {"editable": False}},
        "origins": origins,
        "tool_schemas": 0,
        "version": runtime.VERSION,
    }

    def runner(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv == [str(paths.uv), "--version"]:
            return subprocess.CompletedProcess(argv, 0, runtime.UV_VERSION + "\n", "")
        if len(argv) > 1 and argv[0] == str(bin_directory / "python") and argv[1] == "-I":
            return subprocess.CompletedProcess(argv, 0, json.dumps(evidence) + "\n", "")
        if argv == [str(hermes), "--version"]:
            return subprocess.CompletedProcess(argv, 0, "Hermes Agent v0.18.2\n", "")
        if argv[0] == str(hermes) and argv[-1] == "--help":
            return subprocess.CompletedProcess(argv, 0, "usage --quiet --resume --query\n", "")
        raise AssertionError(argv)

    runner.evidence = evidence  # type: ignore[attr-defined]
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
    runner.evidence["origins"]["model_tools"] = str(outside)
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
    assert command[-5:] == [
        "--frozen",
        "--no-dev",
        "--no-editable",
        "--python",
        "3.11",
    ]
    assert "UV_PROJECT_ENVIRONMENT=" + str(paths.venv) in command
    rendered = " ".join(command).lower()
    assert "proxy" not in rendered
    assert "agentmail" not in rendered
    assert "composio" not in rendered


def test_runtime_installer_cli_rejects_arbitrary_root() -> None:
    with pytest.raises(SystemExit):
        _runtime().main(["--root", "/tmp/runtime"])


def test_failed_runtime_install_removes_builder_owned_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, valid_runner, _calls, uid, gid = _fixture(tmp_path, monkeypatch)

    def failing_runner(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if argv == [str(paths.uv), "--version"]:
            return cast(subprocess.CompletedProcess[str], valid_runner(argv, **kwargs))
        if argv[:1] == ["/usr/bin/sudo"]:
            return subprocess.CompletedProcess(argv, 1, "", "failed")
        raise AssertionError(argv)

    with pytest.raises(ValueError, match="frozen Hermes runtime installation"):
        runtime.install_runtime(
            paths,
            root_uid=uid,
            wheel_gid=gid,
            build_user="_hermesmail",
            build_uid=uid,
            build_gid=gid,
            runner=failing_runner,
            acl_validator=_no_acl,
            provenance_checker=lambda: None,
            probe_parent=tmp_path,
        )
    for path in (
        paths.attestation,
        paths.venv,
        paths.python_installs,
        paths.cache,
        paths.temporary,
    ):
        assert not path.exists()


def test_successful_install_uses_only_temporary_probe_homes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, paths, valid_runner, _calls, uid, gid = _fixture(tmp_path, monkeypatch)
    service_home = tmp_path / "service-home-must-not-exist"
    probe_parent = tmp_path / "probe-homes"
    probe_parent.mkdir(mode=0o700)
    probe_homes: set[Path] = set()

    def populate_runtime() -> None:
        python_real = paths.python_installs / "cpython/bin/python3.11"
        python_real.parent.mkdir(parents=True, exist_ok=True)
        python_real.write_text("reviewed python\n")
        python_real.chmod(0o755)
        bin_directory = paths.venv / "bin"
        site = paths.venv / "lib/python3.11/site-packages"
        bin_directory.mkdir(parents=True, exist_ok=True)
        site.mkdir(parents=True, exist_ok=True)
        (bin_directory / "python").symlink_to(python_real)
        hermes = bin_directory / "hermes"
        hermes.write_text(f"#!{bin_directory / 'python'}\nprint('stub')\n")
        hermes.chmod(0o755)
        for name in ("hermes_cli", "run_agent", "model_tools", "toolsets"):
            (site / (name + ".py")).write_text("# reviewed\n")

    def install_runner(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if argv == [str(paths.uv), "--version"]:
            return cast(subprocess.CompletedProcess[str], valid_runner(argv, **kwargs))
        if argv[:1] == ["/usr/bin/sudo"]:
            populate_runtime()
            return subprocess.CompletedProcess(argv, 0, "", "")
        home = Path(kwargs["env"]["HOME"])
        assert home.parent == probe_parent
        assert home != service_home
        assert home.stat().st_mode & 0o777 == 0o700
        (home / "offline-state").write_text("temporary\n")
        probe_homes.add(home)
        return cast(subprocess.CompletedProcess[str], valid_runner(argv, **kwargs))

    runtime.install_runtime(
        paths,
        root_uid=uid,
        wheel_gid=gid,
        build_user="_hermesmail",
        build_uid=uid,
        build_gid=gid,
        runner=install_runner,
        acl_validator=_no_acl,
        provenance_checker=lambda: None,
        probe_parent=probe_parent,
    )
    assert probe_homes
    assert list(probe_parent.iterdir()) == []
    assert not service_home.exists()
    assert paths.attestation.is_file()
