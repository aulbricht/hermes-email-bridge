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

PROTOCOL = "hermes-email-bridge/1"
HERMES_VERSION = "0.18.2"
MODEL = "gpt-5.5"
PROVIDER = "openai-codex"
TOOLSETS = ["context_engine"]
MAX_TURNS = 1
MAX_PROTOCOL_BYTES = 256 * 1024
_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
_FORBIDDEN_MARKERS = (
    "[HERMES EMAIL BRIDGE",
    "[TRUSTED METADATA]",
    "[UNTRUSTED EMAIL USER CONTENT]",
    "[END UNTRUSTED EMAIL USER CONTENT]",
)


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


def _protocol_record(reply: str, session_id: str) -> bytes:
    payload = {"protocol": PROTOCOL, "reply": reply, "session_id": session_id}
    return (
        json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        + b"\n"
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
        reply = result.get("final_response")
        session_id = result.get("session_id")
        if (
            type(reply) is not str
            or not _valid_reply(reply)
            or type(session_id) is not str
            or _SESSION_ID.fullmatch(session_id) is None
            or result.get("completed") is not True
            or result.get("failed") is not False
            or result.get("partial") is not False
            or result.get("interrupted") is not False
            or result.get("cleanup_errors") not in (None, [])
            or getattr(agent, "session_id", None) != session_id
        ):
            return None
        hermes_cli.session_id = session_id
        candidate = _protocol_record(reply, session_id)
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
