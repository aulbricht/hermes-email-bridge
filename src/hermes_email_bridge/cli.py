"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import logging
import time
from collections.abc import Sequence
from dataclasses import asdict

from . import __version__
from .config import ConfigError, Settings
from .log import configure_logging
from .models import ConversationMapping
from .providers.agentmail import AgentMailProvider
from .providers.base import EmailProvider
from .runner import SubprocessHermesRunner
from .service import BridgeService
from .store import MappingStore
from .webhook import serve_webhooks

logger = logging.getLogger(__name__)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hermes-email-bridge",
        description="Route inbound provider email to Hermes Agent.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    poll = commands.add_parser("poll", help="Poll inbound email")
    poll.add_argument("--continuous", action="store_true", help="Poll until interrupted")
    poll.add_argument("--interval", type=float, help="Override polling interval in seconds")

    commands.add_parser("serve", help="Run the verified webhook server")
    inspect = commands.add_parser("inspect", help="Fetch and normalize one provider message")
    inspect.add_argument("message_id")
    inspect.add_argument("--raw", action="store_true", help="Include the raw provider payload")
    mappings = commands.add_parser("mappings", help="List or rotate persistent mappings")
    mapping_commands = mappings.add_subparsers(dest="mappings_command")
    rotate = mapping_commands.add_parser("rotate", help="Rotate one bridge marker")
    rotate.add_argument("mapping_id", type=int)
    rotate.add_argument("--ttl-days", type=int, default=90)
    purge = commands.add_parser("purge-raw", help="Purge retained raw email payloads")
    purge.add_argument("--older-than-days", type=int)
    commands.add_parser("init-db", help="Initialize the SQLite mapping store")
    return parser


def _provider(settings: Settings) -> EmailProvider:
    api_key, inbox_id = settings.require_agentmail()
    return AgentMailProvider(
        api_key=api_key,
        inbox_id=inbox_id,
        base_url=settings.agentmail_base_url,
        allow_insecure_local_http=settings.agentmail_allow_insecure_local_http,
    )


def _service(
    settings: Settings,
    provider: EmailProvider,
    store: MappingStore,
) -> BridgeService:
    return BridgeService(
        provider=provider,
        store=store,
        runner=SubprocessHermesRunner(
            settings.hermes_command,
            settings.hermes_profile,
            settings.hermes_timeout,
        ),
        send_replies=settings.send_replies,
        dry_run=settings.dry_run,
        store_raw=settings.store_raw,
        raw_retention_days=settings.raw_retention_days,
        allow_subject_resume=settings.allow_subject_resume,
    )


def _masked_mapping(mapping: ConversationMapping) -> dict[str, object]:
    value = asdict(mapping)
    marker = str(value["bridge_marker"])
    suffix = marker[-4:] if len(marker) > 4 else ""
    value["bridge_marker"] = f"v1:****{suffix}"
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        settings = Settings.from_env()
        configure_logging(settings.log_level)
        with MappingStore(settings.db_path) as store:
            if args.command == "init-db":
                print(settings.db_path)
                return 0
            if args.command == "mappings":
                if args.mappings_command == "rotate":
                    try:
                        mapping = store.rotate_mapping_marker(
                            args.mapping_id, ttl_days=args.ttl_days
                        )
                    except KeyError as exc:
                        raise ConfigError(f"mapping {args.mapping_id} does not exist") from exc
                    print(
                        json.dumps(
                            {
                                "id": mapping.id,
                                "bridge_marker": f"v1:{mapping.bridge_marker}",
                                "expires_at": mapping.bridge_marker_expires_at,
                            },
                            default=str,
                        )
                    )
                    return 0
                print(
                    json.dumps(
                        [_masked_mapping(item) for item in store.list_mappings()],
                        default=str,
                    )
                )
                return 0
            if args.command == "purge-raw":
                days = (
                    settings.raw_retention_days
                    if args.older_than_days is None
                    else args.older_than_days
                )
                print(json.dumps({"purged": store.purge_raw(days)}))
                return 0

            provider = _provider(settings)
            if args.command == "inspect":
                message = provider.get(args.message_id)
                print(json.dumps(message.as_dict(include_raw=args.raw), indent=2, default=str))
                return 0

            service = _service(settings, provider, store)
            if args.command == "serve":
                if not settings.agentmail_webhook_secret:
                    raise ConfigError("AGENTMAIL_WEBHOOK_SECRET is required for serve")
                serve_webhooks(
                    service=service,
                    provider=provider,
                    secret=settings.agentmail_webhook_secret,
                    host=settings.webhook_host,
                    port=settings.webhook_port,
                    worker_count=settings.webhook_workers,
                    queue_size=settings.webhook_queue_size,
                )
                return 0

            interval = settings.poll_interval if args.interval is None else args.interval
            if interval <= 0:
                raise ConfigError("poll interval must be positive")
            while True:
                summary = service.poll_once()
                print(json.dumps(asdict(summary)))
                if not args.continuous:
                    return 1 if summary.failed else 0
                time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("bridge stopped", extra={"event": "bridge_stopped"})
        return 130
    except (ConfigError, ValueError, OSError, RuntimeError) as exc:
        logger.error("bridge failed", extra={"event": "bridge_error", "reason": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
