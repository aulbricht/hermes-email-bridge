import os
import plistlib
import subprocess
import tomllib
from pathlib import Path

from hermes_email_bridge import __version__

ROOT = Path(__file__).parents[1]


def test_version_has_one_project_source() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert project["project"]["version"] == "0.3.0"
    assert __version__ == "0.3.0"
    assert '__version__ = "0.3.0"' not in (ROOT / "src/hermes_email_bridge/__init__.py").read_text()


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
    sudoers_path = ROOT / "deploy/macos/hermes-email-agent.sudoers"
    plist_text = plist_path.read_text()
    launcher = launcher_path.read_text()
    wrapper = wrapper_path.read_text()
    sudoers = sudoers_path.read_text()
    combined = plist_text + launcher + wrapper + sudoers
    assert "snowcapconsulting" not in combined
    assert "aulbricht" not in combined
    assert "/Users/" not in combined
    assert "EMAIL_BRIDGE_COMPOSIO_API_KEY" not in combined
    assert "umask 077" in launcher
    assert '!= "600"' in launcher
    if os.name == "posix":
        assert launcher_path.stat().st_mode & 0o111
        assert wrapper_path.stat().st_mode & 0o111
        assert not sudoers_path.stat().st_mode & 0o111

    assert "__BRIDGE_USER__ ALL = (_hermesmail) NOPASSWD:" in sudoers
    assert "/usr/local/libexec/hermes-email-agent" in sudoers
    for fixed in (
        "/var/db/hermes-email-agent/workspace",
        "/Library/Application Support/HermesEmailAgent/hermes-agent/venv/bin/hermes",
        '"--safe-mode"',
        '"no_mcp"',
        '"openai-codex"',
        '"gpt-5.5"',
    ):
        assert fixed in wrapper

    plist = plistlib.loads(plist_path.read_bytes())
    assert plist["RunAtLoad"] is True
    assert plist["KeepAlive"] == {"SuccessfulExit": False}
    assert plist["ThrottleInterval"] == 30
    assert plist["Umask"] == 0o77
    assert plist["WorkingDirectory"] == "__WORKSPACE__"
    assert "HERMES_HOME" not in plist["EnvironmentVariables"]


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
        "-o root -g wheel -m 0755",
        "visudo -cf",
        "-o root -g wheel -m 0440",
        "exactly zero tool schemas",
        "--toolsets no_mcp",
        "inference-only",
        "never copy or reuse another user's profile",
    ):
        assert required.lower() in normalized_readme
    assert (
        "HERMES_COMMAND='/usr/bin/sudo -n -H -u _hermesmail /usr/local/libexec/hermes-email-agent'"
    ) in example


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

    result = subprocess.run(
        [str(ROOT / "deploy/macos/run-email-bridge.sh")],
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
