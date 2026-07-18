"""Environment-backed configuration."""

from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import file_digest
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

from .mapping import normalize_email_address

ISOLATED_HERMES_COMMAND = "/usr/bin/sudo -n -H -u _hermesmail /usr/local/libexec/hermes-email-agent"
ISOLATED_VERIFIER_PATH = Path(
    "/Library/Application Support/HermesEmailAgent/hermes-agent/runtime/"
    "verify-hermes-email-agent.py"
)
ISOLATED_VERIFIER_SHA256 = "77ef28ff214d5b197d765f90d72c9cbd43494e0d6984686f35b4469354259891"
USER_ADAPTER_SHA256 = "0f34ee02a77840f2d476ba3769d8b2e670427ae58c79d279b22b62a62e6623ae"


class ConfigError(ValueError):
    """Raised when bridge configuration is missing or invalid."""


def _bool(value: str, name: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be true or false")


def _domains(value: str, name: str) -> frozenset[str]:
    if not value.strip():
        return frozenset()
    items = value.split(",")
    if any(not item.strip() for item in items):
        raise ConfigError(f"{name} must be comma-separated email domains")
    try:
        return frozenset(
            normalize_email_address(f"bridge@{item.strip().lower().removeprefix('@')}").rsplit(
                "@", 1
            )[1]
            for item in items
        )
    except ValueError as exc:
        raise ConfigError(f"{name} must be comma-separated email domains") from exc


def validate_agentmail_base_url(value: str, *, allow_local_http: bool = False) -> str:
    """Return a normalized, credential-free HTTPS AgentMail API base URL."""

    base_url = value.rstrip("/")
    try:
        parsed = urlsplit(base_url)
        hostname = parsed.hostname
        _port = parsed.port
    except ValueError as exc:
        raise ConfigError("AGENTMAIL_BASE_URL is invalid") from exc
    if not hostname or parsed.username is not None or parsed.password is not None:
        raise ConfigError("AGENTMAIL_BASE_URL must have a host and no credentials")
    if parsed.query or parsed.fragment:
        raise ConfigError("AGENTMAIL_BASE_URL cannot contain a query or fragment")
    if parsed.scheme == "https":
        return base_url
    if hostname.lower() == "localhost":
        is_loopback = True
    else:
        try:
            is_loopback = ip_address(hostname).is_loopback
        except ValueError:
            is_loopback = False
    if parsed.scheme == "http" and allow_local_http and is_loopback:
        return base_url
    raise ConfigError(
        "AGENTMAIL_BASE_URL must use HTTPS; local HTTP requires "
        "AGENTMAIL_ALLOW_INSECURE_LOCAL_HTTP=true and a loopback host"
    )


def _validate_parent_chain(
    path: Path, *, label: str, trusted_uids: frozenset[int] | None = None
) -> None:
    owners = frozenset({0, os.getuid()}) if trusted_uids is None else trusted_uids
    for parent in path.parents:
        details = parent.lstat()
        mode = stat.S_IMODE(details.st_mode)
        root_sticky_directory = details.st_uid == 0 and bool(mode & stat.S_ISVTX)
        if (
            not stat.S_ISDIR(details.st_mode)
            or details.st_uid not in owners
            or (mode & 0o022 and not root_sticky_directory)
        ):
            raise ConfigError(f"HERMES_COMMAND {label} parent path is writable by another account")


def _validate_python_executable(path: Path) -> None:
    try:
        lexical = path.lstat()
        resolved = path.resolve(strict=True)
        details = resolved.lstat()
    except OSError as exc:
        raise ConfigError("HERMES_COMMAND Python executable does not exist") from exc
    if lexical.st_uid not in {0, os.getuid()}:
        raise ConfigError("HERMES_COMMAND Python executable has unsafe ownership")
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid not in {0, os.getuid()}
        or details.st_mode & 0o022
        or not details.st_mode & 0o111
    ):
        raise ConfigError("HERMES_COMMAND Python executable is unsafe")
    _validate_parent_chain(path, label="Python executable")
    if resolved != path:
        _validate_parent_chain(resolved, label="resolved Python executable")


def _preflight_isolated_runtime(
    *,
    verifier: Path = ISOLATED_VERIFIER_PATH,
    expected_hash: str = ISOLATED_VERIFIER_SHA256,
    trusted_uids: frozenset[int] = frozenset({0}),
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    try:
        details = verifier.lstat()
    except OSError as exc:
        raise ConfigError("isolated Hermes protocol-v2 verifier is missing") from exc
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid not in trusted_uids
        or stat.S_IMODE(details.st_mode) != 0o755
    ):
        raise ConfigError("isolated Hermes protocol-v2 verifier has unsafe metadata")
    _validate_parent_chain(
        verifier, label="isolated verifier", trusted_uids=trusted_uids
    )
    with verifier.open("rb") as stream:
        if file_digest(stream, "sha256").hexdigest() != expected_hash:
            raise ConfigError("isolated Hermes runtime must be upgraded for protocol v2")
    completed = runner(
        [str(verifier)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
        text=True,
        timeout=120,
    )
    if completed.returncode != 0 or completed.stderr:
        raise ConfigError("isolated Hermes protocol-v2 attestation failed")
    try:
        evidence = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ConfigError("isolated Hermes protocol-v2 attestation is malformed") from exc
    if (
        type(evidence) is not dict
        or set(evidence) != {
            "attestation",
            "bridge_user",
            "live_canary",
            "tool_schemas",
            "version",
        }
        or evidence.get("attestation") != "verified"
        or type(evidence.get("bridge_user")) is not str
        or not evidence.get("bridge_user")
        or evidence.get("live_canary") is not False
        or evidence.get("tool_schemas") != 0
        or evidence.get("version") != "0.18.2"
        or completed.stdout != json.dumps(evidence, sort_keys=True) + "\n"
    ):
        raise ConfigError("isolated Hermes protocol-v2 attestation is invalid")


def validate_hermes_command(value: str) -> str:
    """Accept the optional isolated wrapper or one fixed user-space adapter invocation."""

    if value == ISOLATED_HERMES_COMMAND:
        return value
    try:
        argv = shlex.split(value)
    except ValueError as exc:
        raise ConfigError("HERMES_COMMAND is invalid") from exc
    if (
        len(argv) not in {4, 6}
        or argv[1:3] != ["-I", "-B"]
        or not Path(argv[0]).is_absolute()
        or not Path(argv[3]).is_absolute()
        or Path(argv[3]).name != "hermes-email-agent-adapter.py"
        or (len(argv) == 6 and argv[4:] != ["--runtime", "openrouter"])
    ):
        raise ConfigError(
            "HERMES_COMMAND must be the isolated wrapper or an absolute Python -I -B "
            "adapter command"
        )
    _validate_python_executable(Path(argv[0]))
    adapter = Path(argv[3])
    if adapter != adapter.resolve() or adapter.is_symlink() or not adapter.is_file():
        raise ConfigError("HERMES_COMMAND adapter must be a regular non-symlink file")
    metadata = adapter.stat()
    if metadata.st_uid not in {0, os.getuid()} or metadata.st_mode & 0o022:
        raise ConfigError("HERMES_COMMAND adapter has unsafe ownership or permissions")
    _validate_parent_chain(adapter, label="adapter")
    with adapter.open("rb") as stream:
        digest = file_digest(stream, "sha256").hexdigest()
    if digest != USER_ADAPTER_SHA256:
        raise ConfigError("HERMES_COMMAND adapter does not match the reviewed release")
    return value


def preflight_hermes_command(value: str) -> str:
    """Revalidate the selected execution boundary immediately before every invocation."""

    if value == ISOLATED_HERMES_COMMAND:
        _preflight_isolated_runtime()
        return value
    return validate_hermes_command(value)


@dataclass(frozen=True, slots=True)
class Settings:
    provider: str
    db_path: Path
    send_replies: bool
    dry_run: bool
    reply_domains: frozenset[str]
    store_raw: bool
    raw_retention_days: int
    allow_subject_resume: bool
    poll_interval: float
    log_level: str
    hermes_command: str
    hermes_timeout: float
    agentmail_api_key: str | None
    agentmail_inbox_id: str | None
    agentmail_webhook_secret: str | None
    agentmail_base_url: str
    agentmail_allow_insecure_local_http: bool
    bridge_composio_api_key: str | None
    composio_connected_account_id: str | None
    composio_inbox_id: str | None
    webhook_host: str
    webhook_port: int
    webhook_queue_size: int

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        values = os.environ if env is None else env
        try:
            poll_interval = float(values.get("EMAIL_BRIDGE_POLL_INTERVAL", "30"))
            hermes_timeout = float(values.get("HERMES_TIMEOUT", "300"))
            webhook_port = int(values.get("EMAIL_BRIDGE_WEBHOOK_PORT", "8787"))
            raw_retention_days = int(values.get("EMAIL_BRIDGE_RAW_RETENTION_DAYS", "30"))
            webhook_queue_size = int(values.get("EMAIL_BRIDGE_WEBHOOK_QUEUE_SIZE", "8"))
        except ValueError as exc:
            raise ConfigError(f"invalid numeric configuration: {exc}") from exc
        if poll_interval <= 0 or hermes_timeout <= 0:
            raise ConfigError("poll interval and Hermes timeout must be positive")
        if not 1 <= webhook_port <= 65535:
            raise ConfigError("webhook port must be between 1 and 65535")
        if raw_retention_days <= 0:
            raise ConfigError("raw retention days must be positive")
        if webhook_queue_size <= 0:
            raise ConfigError("webhook queue size must be positive")

        provider = values.get("EMAIL_BRIDGE_PROVIDER", "agentmail").strip().lower()
        db_path = Path(
            values.get(
                "EMAIL_BRIDGE_DB_PATH",
                "~/.local/state/hermes-email-bridge/bridge.db",
            )
        ).expanduser()
        allow_local_http = _bool(
            values.get("AGENTMAIL_ALLOW_INSECURE_LOCAL_HTTP", "false"),
            "AGENTMAIL_ALLOW_INSECURE_LOCAL_HTTP",
        )
        agentmail_base_url = validate_agentmail_base_url(
            values.get("AGENTMAIL_BASE_URL", "https://api.agentmail.to/v0"),
            allow_local_http=allow_local_http,
        )
        send_replies = _bool(
            values.get("EMAIL_BRIDGE_SEND_REPLIES", "false"),
            "EMAIL_BRIDGE_SEND_REPLIES",
        )
        dry_run = _bool(
            values.get("EMAIL_BRIDGE_DRY_RUN", "true"),
            "EMAIL_BRIDGE_DRY_RUN",
        )
        hermes_command = validate_hermes_command(
            values.get("HERMES_COMMAND", ISOLATED_HERMES_COMMAND)
        )
        return cls(
            provider=provider,
            db_path=db_path,
            send_replies=send_replies,
            dry_run=dry_run,
            reply_domains=_domains(
                values.get("EMAIL_BRIDGE_REPLY_DOMAINS", ""),
                "EMAIL_BRIDGE_REPLY_DOMAINS",
            ),
            store_raw=_bool(
                values.get("EMAIL_BRIDGE_STORE_RAW", "false"),
                "EMAIL_BRIDGE_STORE_RAW",
            ),
            raw_retention_days=raw_retention_days,
            allow_subject_resume=_bool(
                values.get("EMAIL_BRIDGE_ALLOW_SUBJECT_RESUME", "false"),
                "EMAIL_BRIDGE_ALLOW_SUBJECT_RESUME",
            ),
            poll_interval=poll_interval,
            log_level=values.get("EMAIL_BRIDGE_LOG_LEVEL", "INFO").upper(),
            hermes_command=hermes_command,
            hermes_timeout=hermes_timeout,
            agentmail_api_key=values.get("AGENTMAIL_API_KEY"),
            agentmail_inbox_id=values.get("AGENTMAIL_INBOX_ID"),
            agentmail_webhook_secret=values.get("AGENTMAIL_WEBHOOK_SECRET"),
            agentmail_base_url=agentmail_base_url,
            agentmail_allow_insecure_local_http=allow_local_http,
            bridge_composio_api_key=values.get("EMAIL_BRIDGE_COMPOSIO_API_KEY"),
            composio_connected_account_id=values.get("COMPOSIO_AGENT_MAIL_CONNECTED_ACCOUNT_ID"),
            composio_inbox_id=values.get("COMPOSIO_AGENT_MAIL_INBOX_ID"),
            webhook_host=values.get("EMAIL_BRIDGE_WEBHOOK_HOST", "127.0.0.1"),
            webhook_port=webhook_port,
            webhook_queue_size=webhook_queue_size,
        )

    def require_agentmail(self) -> tuple[str, str]:
        if self.provider != "agentmail":
            raise ConfigError(f"unsupported provider: {self.provider}")
        if not self.agentmail_api_key:
            raise ConfigError("AGENTMAIL_API_KEY is required")
        if not self.agentmail_inbox_id:
            raise ConfigError("AGENTMAIL_INBOX_ID is required")
        return self.agentmail_api_key, self.agentmail_inbox_id

    def require_composio_agentmail(self) -> tuple[str, str, str]:
        if self.provider != "composio-agentmail":
            raise ConfigError(f"unsupported provider: {self.provider}")
        if not self.bridge_composio_api_key:
            raise ConfigError("EMAIL_BRIDGE_COMPOSIO_API_KEY is required")
        if not self.composio_connected_account_id:
            raise ConfigError("COMPOSIO_AGENT_MAIL_CONNECTED_ACCOUNT_ID is required")
        if not self.composio_inbox_id:
            raise ConfigError("COMPOSIO_AGENT_MAIL_INBOX_ID is required")
        return (
            self.bridge_composio_api_key,
            self.composio_connected_account_id,
            self.composio_inbox_id,
        )

    def logical_provider(self) -> str:
        if self.provider in {"agentmail", "composio-agentmail"}:
            return "agentmail"
        raise ConfigError(f"unsupported provider: {self.provider}")
