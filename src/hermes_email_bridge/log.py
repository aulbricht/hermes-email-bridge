"""Small JSON formatter for structured, redacted bridge logs."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}
_SENSITIVE = ("authorization", "credential", "password", "secret", "token", "api_key")


def _redact(value: Any, key: str = "") -> Any:
    if any(fragment in key.lower() for fragment in _SENSITIVE):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        value: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        value.update(
            {
                key: _redact(item, key)
                for key, item in record.__dict__.items()
                if key not in _RESERVED and not key.startswith("_")
            }
        )
        if record.exc_info:
            value["exception"] = self.formatException(record.exc_info)
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"invalid log level: {level}")
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(numeric_level)
