from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).parents[1]
MIGRATION_PATH = ROOT / "deploy/macos/quarantine-hermes-email-runtime-v0_3.py"
RUNTIME_INSTALLER_PATH = ROOT / "deploy/macos/install-hermes-email-runtime.py"
TOKEN = "0123456789abcdef01234567"


def _load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _migration() -> Any:
    return _load(MIGRATION_PATH, "hermes_email_runtime_migration")


def _runtime_installer() -> Any:
    return _load(RUNTIME_INSTALLER_PATH, "hermes_email_runtime_for_migration")


def _fixture(tmp_path: Path) -> tuple[Any, Any, int, int]:
    migration = _migration()
    root = tmp_path / "root"
    paths = migration.build_paths(root)
    paths.active_runtime.mkdir(parents=True)
    for path in (
        paths.filesystem_root,
        paths.library,
        paths.application_support,
        paths.product_root,
        paths.install_root,
    ):
        path.chmod(0o755)
    paths.active_runtime.chmod(0o750)
    return migration, paths, os.getuid(), os.getgid()


def _quarantine(migration: Any, paths: Any, uid: int, gid: int, **kwargs: Any) -> Path:
    return cast(
        Path,
        migration.quarantine_runtime(
            paths,
            expected_uid=uid,
            wheel_gid=gid,
            admin_gid=gid,
            require_root=False,
            acl_validator=lambda _paths: None,
            token_factory=lambda: TOKEN,
            **kwargs,
        ),
    )


def test_unknown_legacy_tree_is_atomically_quarantined_without_execution(tmp_path: Path) -> None:
    migration, paths, uid, gid = _fixture(tmp_path)
    incident_marker = tmp_path / "legacy-executed"
    payload = paths.active_runtime / "legacy-hermes"
    payload.write_text(f"#!/bin/sh\nprintf compromised > '{incident_marker}'\n")
    payload.chmod(0o755)
    original_bytes = payload.read_bytes()
    original = paths.active_runtime.lstat()
    observed: list[tuple[Path, Path]] = []

    def rename(source: Path, destination: Path) -> None:
        observed.append((source, destination))
        os.rename(source, destination)

    quarantine = _quarantine(migration, paths, uid, gid, renamer=rename)

    assert observed == [(paths.active_runtime, quarantine)]
    assert quarantine.name == migration.QUARANTINE_PREFIX + TOKEN
    assert not paths.active_runtime.exists()
    assert (quarantine.stat().st_dev, quarantine.stat().st_ino) == (
        original.st_dev,
        original.st_ino,
    )
    assert (quarantine / payload.name).read_bytes() == original_bytes
    assert not incident_marker.exists()


def test_post_rename_failure_never_restores_or_deletes_legacy_runtime(tmp_path: Path) -> None:
    migration, paths, uid, gid = _fixture(tmp_path)
    legacy = paths.active_runtime / "legacy-state"
    legacy.write_text("retain me\n")
    quarantine = paths.install_root / (migration.QUARANTINE_PREFIX + TOKEN)

    def fail_sync(_path: Path) -> None:
        raise OSError("injected directory sync failure")

    with pytest.raises(OSError, match="injected directory sync"):
        _quarantine(migration, paths, uid, gid, directory_sync=fail_sync)

    assert not paths.active_runtime.exists()
    assert (quarantine / legacy.name).read_text() == "retain me\n"


def test_fresh_runtime_installer_can_use_first_install_path_after_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    migration, migration_paths, uid, gid = _fixture(tmp_path)
    (migration_paths.active_runtime / "legacy").write_text("unverified\n")
    quarantine = _quarantine(migration, migration_paths, uid, gid)
    runtime = _runtime_installer()
    uv = tmp_path / "uv"
    uv.write_text("unused by simulated build\n")
    paths = runtime.build_paths(migration_paths.install_root, uv)

    def build(stage: Any, **_kwargs: Any) -> None:
        (stage.runtime_root / "v0.4-generation").write_text("verified simulation\n")

    monkeypatch.setattr(runtime, "build_generation", build)
    monkeypatch.setattr(runtime, "probe_runtime", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(runtime, "verify_attestation", lambda *_args, **_kwargs: None)

    def final_verifier(active: Any) -> None:
        assert (active.runtime_root / "v0.4-generation").read_text() == "verified simulation\n"

    runtime.install_runtime(
        paths,
        root_uid=uid,
        wheel_gid=gid,
        build_user="simulated-builder",
        build_uid=uid,
        build_gid=gid,
        acl_validator=lambda _paths: None,
        provenance_checker=lambda: None,
        probe_parent=tmp_path,
        final_verifier=final_verifier,
    )

    assert (paths.runtime_root / "v0.4-generation").is_file()
    assert (quarantine / "legacy").read_text() == "unverified\n"


@pytest.mark.parametrize("name", [".runtime-stage.stale", ".runtime-backup.stale"])
def test_existing_runtime_transaction_fails_closed(tmp_path: Path, name: str) -> None:
    migration, paths, uid, gid = _fixture(tmp_path)
    (paths.install_root / name).mkdir()
    with pytest.raises(ValueError, match="transaction or quarantine"):
        _quarantine(migration, paths, uid, gid)
    assert paths.active_runtime.is_dir()


def test_existing_quarantine_fails_closed(tmp_path: Path) -> None:
    migration, paths, uid, gid = _fixture(tmp_path)
    (paths.install_root / (migration.QUARANTINE_PREFIX + "f" * 24)).mkdir()
    with pytest.raises(ValueError, match="transaction or quarantine"):
        _quarantine(migration, paths, uid, gid)
    assert paths.active_runtime.is_dir()


def test_destination_collision_after_preflight_fails_closed(tmp_path: Path) -> None:
    migration, paths, uid, gid = _fixture(tmp_path)
    collision = paths.install_root / (migration.QUARANTINE_PREFIX + TOKEN)

    def collide() -> str:
        collision.mkdir()
        return TOKEN

    with pytest.raises(FileExistsError, match="destination already exists"):
        migration.quarantine_runtime(
            paths,
            expected_uid=uid,
            wheel_gid=gid,
            admin_gid=gid,
            require_root=False,
            acl_validator=lambda _paths: None,
            token_factory=collide,
        )
    assert paths.active_runtime.is_dir()


def test_symlinked_runtime_fails_closed(tmp_path: Path) -> None:
    migration, paths, uid, gid = _fixture(tmp_path)
    shutil.rmtree(paths.active_runtime)
    target = tmp_path / "outside"
    target.mkdir()
    paths.active_runtime.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="non-symlink directory"):
        _quarantine(migration, paths, uid, gid)
    assert paths.active_runtime.is_symlink()


def test_symlinked_parent_fails_closed(tmp_path: Path) -> None:
    migration, paths, uid, gid = _fixture(tmp_path)
    shutil.rmtree(paths.library)
    target = tmp_path / "outside-library"
    (target / "Application Support/HermesEmailAgent/hermes-agent/runtime").mkdir(parents=True)
    paths.library.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="non-symlink directory"):
        _quarantine(migration, paths, uid, gid)
    assert paths.library.is_symlink()


def test_wrong_expected_owner_fails_closed(tmp_path: Path) -> None:
    migration, paths, uid, gid = _fixture(tmp_path)
    with pytest.raises(ValueError, match="unsafe ownership"):
        migration.quarantine_runtime(
            paths,
            expected_uid=uid + 1,
            wheel_gid=gid,
            admin_gid=gid,
            require_root=False,
            acl_validator=lambda _paths: None,
        )
    assert paths.active_runtime.is_dir()


@pytest.mark.parametrize("target", ["runtime", "parent"])
def test_group_writable_runtime_or_parent_fails_closed(tmp_path: Path, target: str) -> None:
    migration, paths, uid, gid = _fixture(tmp_path)
    unsafe = paths.active_runtime if target == "runtime" else paths.product_root
    unsafe.chmod(stat.S_IMODE(unsafe.stat().st_mode) | 0o020)
    with pytest.raises(ValueError, match=r"mode|writable"):
        _quarantine(migration, paths, uid, gid)
    assert paths.active_runtime.is_dir()


def test_unexpected_acl_fails_closed(tmp_path: Path) -> None:
    migration, paths, uid, gid = _fixture(tmp_path)

    def reject(_paths: Any) -> None:
        raise ValueError("unexpected ACL")

    with pytest.raises(ValueError, match="unexpected ACL"):
        migration.quarantine_runtime(
            paths,
            expected_uid=uid,
            wheel_gid=gid,
            admin_gid=gid,
            require_root=False,
            acl_validator=reject,
        )
    assert paths.active_runtime.is_dir()


@pytest.mark.parametrize(
    "listing",
    [
        "drwxr-xr-x+ 2 root wheel 64 Jul 14 00:00 runtime\n",
        "drwxr-xr-x 2 root wheel 64 Jul 14 00:00 runtime\n 0: user:someone allow read\n",
    ],
)
def test_production_acl_parser_rejects_named_or_numbered_acl_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, listing: str
) -> None:
    migration, paths, uid, gid = _fixture(tmp_path)
    monkeypatch.setattr(
        migration.subprocess,
        "run",
        lambda *_args, **_kwargs: migration.subprocess.CompletedProcess([], 0, listing, ""),
    )
    with pytest.raises(ValueError, match="unexpected ACL"):
        migration.quarantine_runtime(
            paths,
            expected_uid=uid,
            wheel_gid=gid,
            admin_gid=gid,
            require_root=False,
        )
    assert paths.active_runtime.is_dir()


def test_alternate_active_path_fails_closed(tmp_path: Path) -> None:
    migration, paths, uid, gid = _fixture(tmp_path)
    alternate = replace(paths, active_runtime=paths.install_root / "alternate")
    with pytest.raises(ValueError, match="fixed path plan"):
        _quarantine(migration, alternate, uid, gid)
    assert paths.active_runtime.is_dir()


def test_nonroot_invocation_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    migration, paths, uid, gid = _fixture(tmp_path)
    monkeypatch.setattr(migration.os, "geteuid", lambda: 501)
    with pytest.raises(PermissionError, match="requires root"):
        migration.quarantine_runtime(
            paths,
            expected_uid=uid,
            wheel_gid=gid,
            admin_gid=gid,
            acl_validator=lambda _paths: None,
        )
    assert paths.active_runtime.is_dir()


def test_cli_rejects_every_argument_without_touching_runtime(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    migration, paths, _uid, _gid = _fixture(tmp_path)
    assert migration.main(["--runtime", str(paths.active_runtime)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "runtime quarantine failed\n"
    assert paths.active_runtime.is_dir()
