import os
import plistlib
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
    plist_text = plist_path.read_text()
    launcher = launcher_path.read_text()
    combined = plist_text + launcher
    assert "snowcapconsulting" not in combined
    assert "aulbricht" not in combined
    assert "/Users/" not in combined
    assert "COMPOSIO_API_KEY" not in combined
    assert "umask 077" in launcher
    assert '!= "600"' in launcher
    if os.name == "posix":
        assert launcher_path.stat().st_mode & 0o111

    plist = plistlib.loads(plist_path.read_bytes())
    assert plist["RunAtLoad"] is True
    assert plist["KeepAlive"] == {"SuccessfulExit": False}
    assert plist["ThrottleInterval"] == 30
    assert plist["Umask"] == 0o77
    assert plist["WorkingDirectory"] == "__WORKSPACE__"
