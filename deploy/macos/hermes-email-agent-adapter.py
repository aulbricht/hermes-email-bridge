#!/usr/bin/python3
"""Pinned programmatic Hermes adapter that emits one canonical protocol record."""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import os
import re
import sys
from collections.abc import Sequence

PROTOCOL = "hermes-email-bridge/2"
HERMES_VERSION = "0.18.2"
MODEL = "gpt-5.5"
PROVIDER = "openai-codex"
TOOLSETS = ["context_engine"]
MAX_TURNS = 1
MAX_PROTOCOL_BYTES = 256 * 1024
NORMAL_TURN_EXIT_REASON = "text_response(finish_reason=stop)"
_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
_FORBIDDEN_MARKERS = (
    "[HERMES EMAIL BRIDGE",
    "[TRUSTED METADATA]",
    "[UNTRUSTED EMAIL USER CONTENT]",
    "[END UNTRUSTED EMAIL USER CONTENT]",
)
_DECISION_KEYS = {"action", "reply"}
_ACTIONS = {"reply", "approval_required"}


class _DuplicateKey(ValueError):
    pass


def parse_arguments(arguments: Sequence[str]) -> tuple[str, str | None]:
    resume: str | None = None
    if len(arguments) == 2 and arguments[0] == "--query":
        query = arguments[1]
    elif len(arguments) == 4 and arguments[0] == "--resume" and arguments[2] == "--query":
        resume = arguments[1]
        query = arguments[3]
    else:
        raise ValueError("invalid argument shape")
    if not query or query.startswith("-"):
        raise ValueError("invalid query")
    if resume is not None and _SESSION_ID.fullmatch(resume) is None:
        raise ValueError("invalid session")
    return query, resume


def _valid_reply(reply: str) -> bool:
    if not reply.strip() or any(marker in reply for marker in _FORBIDDEN_MARKERS):
        return False
    for character in reply:
        codepoint = ord(character)
        if (
            codepoint == 0xFEFF
            or codepoint == 0x7F
            or 0x80 <= codepoint <= 0x9F
            or 0xD800 <= codepoint <= 0xDFFF
            or 0x2500 <= codepoint <= 0x259F
            or (codepoint < 0x20 and character not in {"\n", "\t"})
        ):
            return False
    return True


def _reject_duplicate_keys(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKey
        value[key] = item
    return value


def _decision(value: str) -> tuple[str, str] | None:
    try:
        payload = json.loads(value, object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, RecursionError):
        return None
    if type(payload) is not dict or set(payload) != _DECISION_KEYS:
        return None
    action = payload.get("action")
    reply = payload.get("reply")
    if type(action) is not str or action not in _ACTIONS:
        return None
    if type(reply) is not str or not _valid_reply(reply):
        return None
    return action, reply


def _protocol_record(action: str, reply: str, session_id: str) -> bytes:
    payload = {
        "action": action,
        "protocol": PROTOCOL,
        "reply": reply,
        "session_id": session_id,
    }
    return (
        json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        + b"\n"
    )


def _has_zero_tool_surface(cli_module: object, hermes_cli: object, agent: object) -> bool:
    """Attest the actual initialized model tool surface, not just requested toolsets."""

    try:
        definitions = cli_module.get_tool_definitions(  # type: ignore[attr-defined]
            enabled_toolsets=TOOLSETS, quiet_mode=True
        )
        compressor = agent.context_compressor  # type: ignore[attr-defined]
        schemas = compressor.get_tool_schemas()
    except BaseException:
        return False
    return (
        type(definitions) is list
        and not definitions
        and getattr(hermes_cli, "enabled_toolsets", None) == TOOLSETS
        and type(getattr(agent, "tools", None)) is list
        and not agent.tools  # type: ignore[attr-defined]
        and type(schemas) is list
        and not schemas
        and getattr(agent, "_context_engine_tool_names", None) == set()
    )


def _run_hermes(query: str, resume: str | None) -> bytes | None:
    if importlib.metadata.version("hermes-agent") != HERMES_VERSION:
        return None
    cli_module = importlib.import_module("cli")
    hermes_cli = cli_module.HermesCLI(
        model=MODEL,
        toolsets=TOOLSETS,
        provider=PROVIDER,
        max_turns=MAX_TURNS,
        resume=resume,
        ignore_rules=True,
    )
    hermes_cli.tool_progress_mode = "off"
    claimed = False
    protocol: bytes | None = None
    try:
        if not hermes_cli._claim_active_session("cli", stderr=True):
            return None
        claimed = True
        if not hermes_cli._ensure_runtime_credentials():
            return None
        route = hermes_cli._resolve_turn_agent_config(query)
        if not hermes_cli._init_agent(
            model_override=route["model"],
            runtime_override=route["runtime"],
            request_overrides=route.get("request_overrides"),
        ):
            return None
        agent = hermes_cli.agent
        if not _has_zero_tool_surface(cli_module, hermes_cli, agent):
            return None
        agent.quiet_mode = True
        agent.suppress_status_output = True
        agent.stream_delta_callback = None
        agent.tool_gen_callback = None
        result = agent.run_conversation(
            user_message=query,
            conversation_history=hermes_cli.conversation_history,
        )
        if type(result) is not dict:
            return None
        response = result.get("final_response")
        session_id = result.get("session_id")
        decision = _decision(response) if type(response) is str else None
        if (
            decision is None
            or type(session_id) is not str
            or _SESSION_ID.fullmatch(session_id) is None
            or result.get("completed") is not True
            or result.get("failed") is not False
            or result.get("partial") is not False
            or result.get("interrupted") is not False
            or result.get("cleanup_errors") not in (None, [])
            or result.get("turn_exit_reason") != NORMAL_TURN_EXIT_REASON
            or result.get("response_transformed") is not False
            or result.get("response_previewed") is not False
            or "pending_steer" in result
            or result.get("model") != MODEL
            or getattr(agent, "model", None) != MODEL
            or result.get("provider") != PROVIDER
            or getattr(agent, "provider", None) != PROVIDER
            or getattr(agent, "session_id", None) != session_id
            or not _has_zero_tool_surface(cli_module, hermes_cli, agent)
        ):
            return None
        action, reply = decision
        hermes_cli.session_id = session_id
        candidate = _protocol_record(action, reply, session_id)
        if len(candidate) > MAX_PROTOCOL_BYTES:
            return None
        protocol = candidate
    finally:
        if claimed:
            try:
                cli_module._finalize_single_query(hermes_cli)
            except BaseException:
                protocol = None
    return protocol


def _isolate_stdio() -> int:
    saved_stdout = os.dup(1)
    os.set_inheritable(saved_stdout, False)
    devnull = os.open(os.devnull, os.O_RDWR)
    try:
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
    finally:
        os.close(devnull)
    return saved_stdout


def main(arguments: Sequence[str] | None = None) -> int:
    saved_stdout = _isolate_stdio()
    try:
        os.environ.update(
            {
                "HERMES_SAFE_MODE": "1",
                "HERMES_IGNORE_USER_CONFIG": "1",
                "HERMES_IGNORE_RULES": "1",
                "HERMES_SESSION_SOURCE": "tool",
            }
        )
        query, resume = parse_arguments(sys.argv[1:] if arguments is None else arguments)
        protocol = _run_hermes(query, resume)
        if protocol is None:
            return 1
        written = 0
        while written < len(protocol):
            written += os.write(saved_stdout, protocol[written:])
        return 0
    except BaseException:
        return 1
    finally:
        os.close(saved_stdout)


if __name__ == "__main__":
    raise SystemExit(main())
