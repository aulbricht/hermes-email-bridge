from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
INSTALLER_PATH = ROOT / "deploy/macos/install-hermes-email-agent.py"


def _installer() -> Any:
    spec = importlib.util.spec_from_file_location("hermes_email_agent_installer", INSTALLER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _fixture(tmp_path: Path) -> tuple[Any, Any, int, int]:
    installer = _installer()
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "hermes-email-agent-wrapper.py").write_text("#!/usr/bin/python3\n")
    (assets / "hermes-email-boundary-verify.py").write_text("#!/usr/bin/python3\n")
    (assets / "hermes-email-agent.sudoers").write_text(
        "Defaults:__BRIDGE_USER__ env_reset\n"
        "__BRIDGE_USER__ ALL = (_hermesmail) NOPASSWD: /usr/local/libexec/hermes-email-agent\n"
        "__BRIDGE_USER__ ALL = (root) NOPASSWD: "
        '/usr/local/libexec/hermes-email-boundary-verify ""\n'
    )
    system_root = tmp_path / "system"
    for relative in ("usr/local", "private/etc/sudoers.d"):
        path = system_root / relative
        path.mkdir(parents=True)
    system_root.chmod(0o755)
    for relative in (
        "usr",
        "usr/local",
        "private",
        "private/etc",
        "private/etc/sudoers.d",
    ):
        (system_root / relative).chmod(0o755)
    return installer, installer.build_plan(system_root, assets), os.getuid(), os.getgid()


def _no_acl(_path: Path) -> bool:
    return False


def _valid_sudoers(path: Path) -> None:
    rendered = path.read_text()
    assert "__BRIDGE_USER__" not in rendered
    assert rendered.count("bridge_user") == 3


def _existing_install(plan: Any) -> None:
    plan.libexec.mkdir(mode=0o755)
    plan.wrapper_destination.write_text("old wrapper\n")
    plan.wrapper_destination.chmod(0o755)
    plan.helper_destination.write_text("old helper\n")
    plan.helper_destination.chmod(0o755)
    plan.sudoers_destination.write_text("old sudoers\n")
    plan.sudoers_destination.chmod(0o440)


def _assert_existing_restored(plan: Any) -> None:
    assert plan.wrapper_destination.read_text() == "old wrapper\n"
    assert stat.S_IMODE(plan.wrapper_destination.stat().st_mode) == 0o755
    assert plan.helper_destination.read_text() == "old helper\n"
    assert stat.S_IMODE(plan.helper_destination.stat().st_mode) == 0o755
    assert plan.sudoers_destination.read_text() == "old sudoers\n"
    assert stat.S_IMODE(plan.sudoers_destination.stat().st_mode) == 0o440


def test_installer_creates_missing_libexec_and_atomically_installs_files(tmp_path: Path) -> None:
    installer, plan, uid, gid = _fixture(tmp_path)
    actions = installer.install(
        plan,
        "bridge_user",
        expected_uid=uid,
        expected_gid=gid,
        mutate=True,
        require_root=False,
        acl_checker=_no_acl,
        sudoers_validator=_valid_sudoers,
    )
    assert actions[0].startswith("create ")
    assert stat.S_IMODE(plan.libexec.stat().st_mode) == 0o755
    assert plan.wrapper_destination.read_text() == "#!/usr/bin/python3\n"
    assert plan.helper_destination.read_text() == "#!/usr/bin/python3\n"
    assert stat.S_IMODE(plan.wrapper_destination.stat().st_mode) == 0o755
    assert "bridge_user" in plan.sudoers_destination.read_text()
    assert stat.S_IMODE(plan.sudoers_destination.stat().st_mode) == 0o440


def test_installer_dry_plan_does_not_create_missing_directory(tmp_path: Path) -> None:
    installer, plan, uid, gid = _fixture(tmp_path)
    actions = installer.install(
        plan,
        "bridge-user",
        expected_uid=uid,
        expected_gid=gid,
        mutate=False,
        acl_checker=_no_acl,
        sudoers_validator=lambda _path: None,
    )
    assert not plan.libexec.exists()
    assert actions == (
        f"create {plan.libexec} root:wheel 0755",
        f"install {plan.wrapper_destination} root:wheel 0755",
        f"install {plan.helper_destination} root:wheel 0755",
        f"install {plan.sudoers_destination} root:wheel 0440",
    )


@pytest.mark.parametrize("name", ["", "-option", "bad/name", "bad\nname", "a" * 33])
def test_installer_rejects_unsafe_bridge_user(name: str) -> None:
    with pytest.raises(ValueError, match="narrow"):
        _installer().validate_bridge_user(name)


def test_installer_requires_exact_placeholder_count() -> None:
    installer = _installer()
    with pytest.raises(ValueError, match="exactly three"):
        installer.render_sudoers("__BRIDGE_USER__ only once", "bridge_user")
    with pytest.raises(ValueError, match="rendering failed"):
        installer.render_sudoers(
            "__BRIDGE_USER__ and __BRIDGE_USER__ and __BRIDGE_USER__ and __UNRESOLVED__",
            "bridge_user",
        )


def test_installer_rejects_symlinked_source(tmp_path: Path) -> None:
    installer, plan, uid, gid = _fixture(tmp_path)
    plan.wrapper_source.unlink()
    plan.wrapper_source.symlink_to(tmp_path / "attacker-source")
    with pytest.raises(ValueError, match="safely open"):
        installer.install(
            plan,
            "bridge_user",
            expected_uid=uid,
            expected_gid=gid,
            mutate=False,
            acl_checker=_no_acl,
            sudoers_validator=lambda _path: None,
        )


def test_installer_rejects_symlinked_trusted_path(tmp_path: Path) -> None:
    installer, plan, uid, gid = _fixture(tmp_path)
    target = tmp_path / "attacker-controlled"
    target.mkdir()
    plan.libexec.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        installer.install(
            plan,
            "bridge_user",
            expected_uid=uid,
            expected_gid=gid,
            mutate=False,
            acl_checker=_no_acl,
            sudoers_validator=lambda _path: None,
        )


def test_installer_rejects_symlinked_destination(tmp_path: Path) -> None:
    installer, plan, uid, gid = _fixture(tmp_path)
    plan.libexec.mkdir(mode=0o755)
    plan.wrapper_destination.symlink_to(tmp_path / "attacker-file")
    with pytest.raises(ValueError, match="symlink"):
        installer.install(
            plan,
            "bridge_user",
            expected_uid=uid,
            expected_gid=gid,
            mutate=False,
            acl_checker=_no_acl,
            sudoers_validator=lambda _path: None,
        )


def test_installer_rejects_unsafe_mode_owner_and_acl(tmp_path: Path) -> None:
    installer, plan, uid, gid = _fixture(tmp_path)
    plan.usr_local.chmod(0o777)
    with pytest.raises(ValueError, match="mode 0755"):
        installer.install(
            plan,
            "bridge_user",
            expected_uid=uid,
            expected_gid=gid,
            mutate=False,
            acl_checker=_no_acl,
            sudoers_validator=lambda _path: None,
        )
    plan.usr_local.chmod(0o755)
    with pytest.raises(ValueError, match="ownership"):
        installer.install(
            plan,
            "bridge_user",
            expected_uid=uid + 1,
            expected_gid=gid,
            mutate=False,
            acl_checker=_no_acl,
            sudoers_validator=lambda _path: None,
        )
    with pytest.raises(ValueError, match="ACL"):
        installer.install(
            plan,
            "bridge_user",
            expected_uid=uid,
            expected_gid=gid,
            mutate=False,
            acl_checker=lambda path: path == plan.usr_local,
            sudoers_validator=lambda _path: None,
        )


def test_invalid_sudoers_fails_before_creating_libexec(tmp_path: Path) -> None:
    installer, plan, uid, gid = _fixture(tmp_path)

    def reject(_path: Path) -> None:
        raise ValueError("invalid sudoers")

    with pytest.raises(ValueError, match="invalid sudoers"):
        installer.install(
            plan,
            "bridge_user",
            expected_uid=uid,
            expected_gid=gid,
            mutate=True,
            require_root=False,
            acl_checker=_no_acl,
            sudoers_validator=reject,
        )
    assert not plan.libexec.exists()


def test_wrapper_replace_failure_leaves_no_partial_install(tmp_path: Path) -> None:
    installer, plan, uid, gid = _fixture(tmp_path)

    def fail_wrapper(_source: Path, destination: Path) -> None:
        if destination == plan.wrapper_destination:
            raise OSError("injected wrapper replace failure")
        os.replace(_source, destination)

    with pytest.raises(OSError, match="wrapper replace"):
        installer.install(
            plan,
            "bridge_user",
            expected_uid=uid,
            expected_gid=gid,
            mutate=True,
            require_root=False,
            acl_checker=_no_acl,
            sudoers_validator=_valid_sudoers,
            replacer=fail_wrapper,
        )
    assert not plan.libexec.exists()
    assert not plan.sudoers_destination.exists()


def test_libexec_chown_failure_rolls_back_new_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer, plan, uid, gid = _fixture(tmp_path)
    before = (set(plan.usr_local.iterdir()), set(plan.sudoers_directory.iterdir()))
    real_chown = installer.os.chown

    def fail_libexec_chown(path: Path, owner: int, group: int) -> None:
        if Path(path) == plan.libexec:
            raise OSError("injected libexec chown failure")
        real_chown(path, owner, group)

    monkeypatch.setattr(installer.os, "chown", fail_libexec_chown)
    with pytest.raises(OSError, match="libexec chown"):
        installer.install(
            plan,
            "bridge_user",
            expected_uid=uid,
            expected_gid=gid,
            mutate=True,
            require_root=False,
            acl_checker=_no_acl,
            sudoers_validator=_valid_sudoers,
        )
    assert not plan.libexec.exists()
    assert not plan.wrapper_destination.exists()
    assert not plan.sudoers_destination.exists()
    assert (set(plan.usr_local.iterdir()), set(plan.sudoers_directory.iterdir())) == before


def test_libexec_chmod_failure_rolls_back_new_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer, plan, uid, gid = _fixture(tmp_path)
    before = (set(plan.usr_local.iterdir()), set(plan.sudoers_directory.iterdir()))
    real_chmod = installer.os.chmod

    def fail_libexec_chmod(path: Path, mode: int) -> None:
        if Path(path) == plan.libexec:
            raise OSError("injected libexec chmod failure")
        real_chmod(path, mode)

    monkeypatch.setattr(installer.os, "chmod", fail_libexec_chmod)
    with pytest.raises(OSError, match="libexec chmod"):
        installer.install(
            plan,
            "bridge_user",
            expected_uid=uid,
            expected_gid=gid,
            mutate=True,
            require_root=False,
            acl_checker=_no_acl,
            sudoers_validator=_valid_sudoers,
        )
    assert not plan.libexec.exists()
    assert not plan.wrapper_destination.exists()
    assert not plan.sudoers_destination.exists()
    assert (set(plan.usr_local.iterdir()), set(plan.sudoers_directory.iterdir())) == before


def test_sudoers_replace_failure_restores_existing_authorized_files(tmp_path: Path) -> None:
    installer, plan, uid, gid = _fixture(tmp_path)
    _existing_install(plan)

    def fail_sudoers(source: Path, destination: Path) -> None:
        if destination == plan.sudoers_destination:
            raise OSError("injected sudoers replace failure")
        os.replace(source, destination)

    with pytest.raises(OSError, match="sudoers replace"):
        installer.install(
            plan,
            "bridge_user",
            expected_uid=uid,
            expected_gid=gid,
            mutate=True,
            require_root=False,
            acl_checker=_no_acl,
            sudoers_validator=_valid_sudoers,
            replacer=fail_sudoers,
        )
    _assert_existing_restored(plan)


@pytest.mark.parametrize("tampered", ["wrapper", "helper", "sudoers"])
def test_final_byte_mismatch_restores_existing_authorized_files(
    tmp_path: Path, tampered: str
) -> None:
    installer, plan, uid, gid = _fixture(tmp_path)
    _existing_install(plan)

    def replace_then_tamper(source: Path, destination: Path) -> None:
        os.replace(source, destination)
        if (
            (tampered == "wrapper" and destination == plan.wrapper_destination)
            or (tampered == "helper" and destination == plan.helper_destination)
            or (tampered == "sudoers" and destination == plan.sudoers_destination)
        ):
            destination.chmod(0o600)
            destination.write_bytes(destination.read_bytes() + b" ")
            destination.chmod(0o440 if tampered == "sudoers" else 0o755)

    with pytest.raises(ValueError, match=r"installed .* bytes"):
        installer.install(
            plan,
            "bridge_user",
            expected_uid=uid,
            expected_gid=gid,
            mutate=True,
            require_root=False,
            acl_checker=_no_acl,
            sudoers_validator=_valid_sudoers,
            replacer=replace_then_tamper,
        )
    _assert_existing_restored(plan)


def test_final_visudo_failure_restores_both_existing_files(tmp_path: Path) -> None:
    installer, plan, uid, gid = _fixture(tmp_path)
    _existing_install(plan)
    validations = 0

    def fail_final(path: Path) -> None:
        nonlocal validations
        validations += 1
        if validations == 3:
            raise ValueError("injected final visudo failure")
        if validations < 3:
            _valid_sudoers(path)

    with pytest.raises(ValueError, match="final visudo"):
        installer.install(
            plan,
            "bridge_user",
            expected_uid=uid,
            expected_gid=gid,
            mutate=True,
            require_root=False,
            acl_checker=_no_acl,
            sudoers_validator=fail_final,
        )
    _assert_existing_restored(plan)


def test_final_path_validation_failure_restores_existing_files(tmp_path: Path) -> None:
    installer, plan, uid, gid = _fixture(tmp_path)
    _existing_install(plan)

    wrapper_checks = 0

    def fail_final_acl(path: Path) -> bool:
        nonlocal wrapper_checks
        if path == plan.wrapper_destination:
            wrapper_checks += 1
            return wrapper_checks == 2
        return False

    with pytest.raises(ValueError, match="ACL"):
        installer.install(
            plan,
            "bridge_user",
            expected_uid=uid,
            expected_gid=gid,
            mutate=True,
            require_root=False,
            acl_checker=fail_final_acl,
            sudoers_validator=_valid_sudoers,
        )
    _assert_existing_restored(plan)


@pytest.mark.skipif(
    sys.platform != "darwin"
    or not Path("/usr/bin/python3").exists()
    or Path("/usr/local/libexec").exists(),
    reason="requires the pre-install macOS system-Python state",
)
def test_macos_system_python_dry_run_plans_missing_libexec() -> None:
    result = subprocess.run(
        [
            "/usr/bin/python3",
            str(INSTALLER_PATH),
            "--bridge-user",
            "bridgeuser",
            "--dry-run",
        ],
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert "create /usr/local/libexec root:wheel 0755" in result.stdout
    assert "install /usr/local/libexec/hermes-email-agent root:wheel 0755" in result.stdout
