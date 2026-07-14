import os
import plistlib
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from hermes_email_bridge import __version__

ROOT = Path(__file__).parents[1]


def test_version_has_one_project_source() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert project["project"]["version"] == "0.4.0"
    assert __version__ == "0.4.0"
    assert '__version__ = "0.4.0"' not in (ROOT / "src/hermes_email_bridge/__init__.py").read_text()


def test_docs_and_example_config_cover_composio_allowlisting_and_start_now() -> None:
    readme = (ROOT / "README.md").read_text()
    example = (ROOT / ".env.example").read_text()
    for required in (
        "EMAIL_BRIDGE_PROVIDER=composio-agentmail",
        "EMAIL_BRIDGE_COMPOSIO_API_KEY",
        "COMPOSIO_AGENT_MAIL_CONNECTED_ACCOUNT_ID",
        "COMPOSIO_AGENT_MAIL_INBOX_ID",
        "allowlist add person@example.com",
        "init-db --start-now",
        "Proxy Execute",
    ):
        assert required in readme or required in example


def test_macos_assets_are_generic_and_fail_closed() -> None:
    plist_path = ROOT / "deploy/macos/com.example.hermes.email-bridge.plist"
    launcher_path = ROOT / "deploy/macos/run-email-bridge.sh"
    wrapper_path = ROOT / "deploy/macos/hermes-email-agent-wrapper.py"
    adapter_path = ROOT / "deploy/macos/hermes-email-agent-adapter.py"
    helper_path = ROOT / "deploy/macos/hermes-email-boundary-verify.py"
    fetcher_path = ROOT / "deploy/macos/fetch-hermes-email-agent.py"
    probe_path = ROOT / "deploy/macos/verify-hermes-email-agent.py"
    runtime_installer_path = ROOT / "deploy/macos/install-hermes-email-runtime.py"
    installer_path = ROOT / "deploy/macos/install-hermes-email-agent.py"
    sudoers_path = ROOT / "deploy/macos/hermes-email-agent.sudoers"
    build_constraint_path = ROOT / "deploy/macos/hermes-email-build-constraints.txt"
    plist_text = plist_path.read_text()
    launcher = launcher_path.read_text()
    wrapper = wrapper_path.read_text()
    sudoers = sudoers_path.read_text()
    adapter = adapter_path.read_text()
    combined = plist_text + launcher + wrapper + adapter + helper_path.read_text() + sudoers
    assert "snowcapconsulting" not in combined
    assert "aulbricht" not in combined
    assert "/Users/" not in combined
    assert "EMAIL_BRIDGE_COMPOSIO_API_KEY" not in combined
    assert "umask 077" in launcher
    assert '!= "600"' in launcher
    if os.name == "posix":
        assert launcher_path.stat().st_mode & 0o111
        assert wrapper_path.stat().st_mode & 0o111
        assert adapter_path.stat().st_mode & 0o111
        assert helper_path.stat().st_mode & 0o111
        assert fetcher_path.stat().st_mode & 0o111
        assert probe_path.stat().st_mode & 0o111
        assert runtime_installer_path.stat().st_mode & 0o111
        assert installer_path.stat().st_mode & 0o111
        assert not sudoers_path.stat().st_mode & 0o111
        assert not build_constraint_path.stat().st_mode & 0o111

    assert "__BRIDGE_USER__ ALL = (_hermesmail) NOPASSWD:" in sudoers
    assert "/usr/local/libexec/hermes-email-agent" in sudoers
    assert (
        '__BRIDGE_USER__ ALL = (root) NOPASSWD: /usr/local/libexec/hermes-email-boundary-verify ""'
    ) in sudoers
    for fixed in (
        "/var/db/hermes-email-agent/workspace",
        "/Library/Application Support/HermesEmailAgent/hermes-agent/runtime/venv/bin/python",
        "hermes-email-agent-adapter.py",
        '"-I"',
        '"-B"',
    ):
        assert fixed in wrapper
    for fixed in (
        'PROTOCOL = "hermes-email-bridge/1"',
        'HERMES_VERSION = "0.18.2"',
        'TOOLSETS = ["context_engine"]',
        'PROVIDER = "openai-codex"',
        'MODEL = "gpt-5.5"',
        "os.dup2(devnull, 1)",
        "_finalize_single_query",
    ):
        assert fixed in adapter
    installer = (ROOT / "deploy/macos/install-hermes-email-agent.py").read_text()
    assert 'rooted("/usr/local/libexec")' in installer
    assert 'rooted("/private/etc/sudoers.d")' in installer
    assert "O_NOFOLLOW" in installer
    assert "visudo" in installer
    fetcher = fetcher_path.read_text()
    assert "codeload.github.com/NousResearch/hermes-agent/tar.gz/" in fetcher
    assert "ProxyHandler({})" in fetcher
    assert "MAX_DOWNLOAD_BYTES" in fetcher
    assert "PROVENANCE_FILE" in fetcher
    runtime_installer = runtime_installer_path.read_text()
    assert "get_tool_definitions" in runtime_installer
    assert 'enabled_toolsets=["context_engine"]' in runtime_installer
    assert "ADAPTER_SHA256" in runtime_installer
    assert '"adapter_protocol": "hermes-email-bridge/1"' in runtime_installer
    assert "--no-editable" in runtime_installer
    assert "LOCK_SHA256" in runtime_installer
    assert "runtime-attestation.json" in runtime_installer
    assert "temporary_probe_home" in runtime_installer
    assert 'BUILD_ACCOUNT = "_hermesbuild"' in runtime_installer
    assert "--build-constraints" in runtime_installer
    assert "--require-hashes" in runtime_installer
    assert "--no-build" in runtime_installer
    assert "/var/db/hermes-email-agent" not in runtime_installer
    probe = probe_path.read_text()
    assert "installed wrapper bytes do not match" in probe
    assert "privileged boundary attestation" in probe
    assert "installed boundary helper bytes do not match" in probe

    plist = plistlib.loads(plist_path.read_bytes())
    assert plist["RunAtLoad"] is True
    assert plist["KeepAlive"] == {"SuccessfulExit": False}
    assert plist["ThrottleInterval"] == 30
    assert plist["Umask"] == 0o77
    assert plist["WorkingDirectory"] == "__WORKSPACE__"
    assert "HERMES_HOME" not in plist["EnvironmentVariables"]


def test_linux_systemd_sudo_and_wrapper_assets_are_fail_closed() -> None:
    directory = ROOT / "deploy/linux"
    wrapper = (directory / "hermes-email-agent-wrapper.py").read_text()
    helper = (directory / "hermes-email-boundary-verify.py").read_text()
    sudoers = (directory / "hermes-email-agent.sudoers").read_text()
    unit = (directory / "hermes-email-bridge.service").read_text()
    assert "/opt/hermes-email-agent/runtime/venv/bin/python" in wrapper
    assert '"-I"' in wrapper and '"-B"' in wrapper
    assert "hermes-email-agent-adapter.py" in wrapper
    assert "ADAPTER_SHA256" in helper and "WRAPPER_SHA256" in helper
    assert sudoers.count("__BRIDGE_USER__") == 3
    assert "(_hermesmail) NOPASSWD: /usr/local/libexec/hermes-email-agent" in sudoers
    assert "ExecStartPre=/usr/bin/sudo -n -H -u root" in unit
    assert "ProtectSystem=strict" in unit
    assert "UMask=0077" in unit
    readme = (ROOT / "README.md").read_text()
    assert "deploy/macos/hermes-email-agent-adapter.py" in readme
    assert "platform-neutral shared adapter" in readme
    assert not (directory / "hermes-email-agent-adapter.py").exists()


def test_shipping_docs_and_assets_have_no_deployment_personalization() -> None:
    paths = [ROOT / "README.md", ROOT / ".env.example", *(ROOT / "deploy").rglob("*")]
    content = "\n".join(
        path.read_text() for path in paths if path.is_file() and "__pycache__" not in path.parts
    ).lower()
    for forbidden in (
        "jarvis",
        "snowcapconsulting",
        "@gmail.com",
        "/users/allen",
    ):
        assert forbidden not in content


def test_macos_isolation_installation_requirements_are_documented() -> None:
    readme = (ROOT / "README.md").read_text()
    normalized_readme = " ".join(readme.split()).lower()
    example = (ROOT / ".env.example").read_text()
    for required in (
        "Hermes Agent **0.18.2**",
        "dscl . -list /Users UniqueID",
        "dscl . -list /Groups PrimaryGroupID",
        "IsHidden 1",
        "-m 0700 /var/db/hermes-email-agent",
        "-m 0700 /var/db/hermes-email-agent/workspace",
        "test -x /usr/bin/python3",
        "root:wheel `0755`",
        "visudo",
        "root:wheel `0440`",
        "install-hermes-email-agent.py",
        "system Python 3.9.6",
        "--dry-run",
        "--check",
        "exactly zero tool schemas",
        "--toolsets context_engine",
        "inference-only",
        "never copy or reuse another user's profile",
        "_hermesbuild",
        "NFSHomeDirectory /var/empty",
        "supplementary group membership",
        "--build-constraints",
        "--require-hashes",
        "--no-build",
        "byte-compare",
    ):
        assert required.lower() in normalized_readme
    for pin in (
        "4281151ae859241351ba14d8c7682dc67ff4c126",
        "731f785d0373c81e7fb3d18ac5f4a1b6f9d6e3b94d2ae56a5b63133045bd2c68",
        "8d03d04a404c641e1c9642f0482e2d8752c57da02da94d612a5f30883b25fbca",
        "f63ec276fa13f8f392542a334c0f58f36833b24304831e5f4c221e2edf7a16f3",
        "a7d4688bc5ddc6d0bd3a0ee477b8f68c6bf7d4d27345cf9e54901d9e153e8f52",
        "fdd925d5c5d9f62e4b74b30d6dd7828ce236fd6ed998a08d81de62ce5a6310d6",
    ):
        assert pin in readme
    assert "codeload.github.com/NousResearch/hermes-agent/tar.gz/" in readme
    assert "locally generated `git archive`" in readme
    assert (
        "HERMES_COMMAND='/usr/bin/sudo -n -H -u _hermesmail /usr/local/libexec/hermes-email-agent'"
    ) in example


@pytest.mark.skipif(sys.platform != "darwin", reason="launcher uses BSD stat")
def test_macos_launcher_sources_realistic_protected_environment(tmp_path: Path) -> None:
    venv_bin = tmp_path / "venv/bin"
    venv_bin.mkdir(parents=True)
    fake_cli = venv_bin / "hermes-email-bridge"
    fake_cli.write_text(
        "#!/bin/sh\n"
        "printf 'argv=%s\\n' \"$*\"\n"
        "printf 'command=%s\\n' \"$HERMES_COMMAND\"\n"
        "printf 'db=%s\\n' \"$EMAIL_BRIDGE_DB_PATH\"\n"
    )
    fake_cli.chmod(0o755)
    env_file = tmp_path / "service.env"
    env_file.write_text(
        f"EMAIL_BRIDGE_VENV='{tmp_path / 'venv'}'\n"
        "HERMES_COMMAND='/usr/bin/sudo -n -H -u _hermesmail "
        "/usr/local/libexec/hermes-email-agent'\n"
        f"EMAIL_BRIDGE_DB_PATH='{tmp_path / 'state/bridge.db'}'\n"
    )
    env_file.chmod(0o600)
    launcher = tmp_path / "run-email-bridge.sh"
    launcher_text = (ROOT / "deploy/macos/run-email-bridge.sh").read_text()
    fixed_verifier = (
        "/Library/Application Support/HermesEmailAgent/hermes-agent/"
        "runtime/verify-hermes-email-agent.py"
    )
    assert launcher_text.index(fixed_verifier) < (launcher_text.index('. "$EMAIL_BRIDGE_ENV_FILE"'))
    launcher.write_text(launcher_text.replace(fixed_verifier, "/usr/bin/true"))
    launcher.chmod(0o755)

    result = subprocess.run(
        [str(launcher)],
        env={
            "EMAIL_BRIDGE_ENV_FILE": str(env_file),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        },
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout == ""
    assert "argv=poll --continuous" in result.stderr
    assert (
        "command=/usr/bin/sudo -n -H -u _hermesmail /usr/local/libexec/hermes-email-agent"
    ) in result.stderr
    assert f"db={tmp_path / 'state/bridge.db'}" in result.stderr
