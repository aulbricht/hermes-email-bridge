"""Safe bridge-marker and subject normalization helpers."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_MARKER = re.compile(r"v1:([A-Za-z0-9_-]{20,128})")
_PREFIX = re.compile(r"^\s*(?:(?:re|fw|fwd)\s*:\s*)+", re.IGNORECASE)


def normalize_subject(subject: str) -> str:
    return " ".join(_PREFIX.sub("", subject).split()).casefold()


def extract_bridge_marker(raw_payload: Mapping[str, Any]) -> str | None:
    """Read an opaque marker only from provider metadata or a dedicated header.

    Email bodies and subjects are deliberately never scanned for routing controls.
    Markers are random capabilities that map to an existing database record; they
    never contain a session ID or other executable bridge instruction.
    """

    provider_metadata = raw_payload.get("_bridge")
    candidates: list[Any] = []
    if isinstance(provider_metadata, Mapping):
        candidates.append(provider_metadata.get("marker"))
    headers = raw_payload.get("headers")
    if isinstance(headers, Mapping):
        candidates.extend(
            value for key, value in headers.items() if str(key).lower() == "x-hermes-bridge"
        )
    for candidate in candidates:
        values = candidate if isinstance(candidate, list) else [candidate]
        for value in values:
            match = _MARKER.fullmatch(str(value or "").strip())
            if match:
                return match.group(1)
    return None
