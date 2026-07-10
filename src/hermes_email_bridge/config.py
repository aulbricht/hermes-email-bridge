"""Environment-backed configuration."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


class ConfigError(ValueError):
    """Raised when bridge configuration is missing or invalid."""


def _bool(value: str, name: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be true or false")


@dataclass(frozen=True, slots=True)
class Settings:
    provider: str
    db_path: Path
    send_replies: bool
    dry_run: bool
    store_raw: bool
    poll_interval: float
    log_level: str
    hermes_command: str
    hermes_profile: str
    hermes_timeout: float
    agentmail_api_key: str | None
    agentmail_inbox_id: str | None
    agentmail_webhook_secret: str | None
    agentmail_base_url: str
    webhook_host: str
    webhook_port: int

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        values = os.environ if env is None else env
        try:
            poll_interval = float(values.get("EMAIL_BRIDGE_POLL_INTERVAL", "30"))
            hermes_timeout = float(values.get("HERMES_TIMEOUT", "300"))
            webhook_port = int(values.get("EMAIL_BRIDGE_WEBHOOK_PORT", "8787"))
        except ValueError as exc:
            raise ConfigError(f"invalid numeric configuration: {exc}") from exc
        if poll_interval <= 0 or hermes_timeout <= 0:
            raise ConfigError("poll interval and Hermes timeout must be positive")
        if not 1 <= webhook_port <= 65535:
            raise ConfigError("webhook port must be between 1 and 65535")

        provider = values.get("EMAIL_BRIDGE_PROVIDER", "agentmail").strip().lower()
        db_path = Path(
            values.get(
                "EMAIL_BRIDGE_DB_PATH",
                "~/.local/state/hermes-email-bridge/bridge.db",
            )
        ).expanduser()
        return cls(
            provider=provider,
            db_path=db_path,
            send_replies=_bool(
                values.get("EMAIL_BRIDGE_SEND_REPLIES", "false"),
                "EMAIL_BRIDGE_SEND_REPLIES",
            ),
            dry_run=_bool(
                values.get("EMAIL_BRIDGE_DRY_RUN", "true"),
                "EMAIL_BRIDGE_DRY_RUN",
            ),
            store_raw=_bool(
                values.get("EMAIL_BRIDGE_STORE_RAW", "true"),
                "EMAIL_BRIDGE_STORE_RAW",
            ),
            poll_interval=poll_interval,
            log_level=values.get("EMAIL_BRIDGE_LOG_LEVEL", "INFO").upper(),
            hermes_command=values.get("HERMES_COMMAND", "hermes chat --quiet --source tool"),
            hermes_profile=values.get("HERMES_PROFILE", "default"),
            hermes_timeout=hermes_timeout,
            agentmail_api_key=values.get("AGENTMAIL_API_KEY"),
            agentmail_inbox_id=values.get("AGENTMAIL_INBOX_ID"),
            agentmail_webhook_secret=values.get("AGENTMAIL_WEBHOOK_SECRET"),
            agentmail_base_url=values.get(
                "AGENTMAIL_BASE_URL", "https://api.agentmail.to/v0"
            ).rstrip("/"),
            webhook_host=values.get("EMAIL_BRIDGE_WEBHOOK_HOST", "127.0.0.1"),
            webhook_port=webhook_port,
        )

    def require_agentmail(self) -> tuple[str, str]:
        if self.provider != "agentmail":
            raise ConfigError(f"unsupported provider: {self.provider}")
        if not self.agentmail_api_key:
            raise ConfigError("AGENTMAIL_API_KEY is required")
        if not self.agentmail_inbox_id:
            raise ConfigError("AGENTMAIL_INBOX_ID is required")
        return self.agentmail_api_key, self.agentmail_inbox_id
