"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict

from . import __version__
from .config import ConfigError, Settings, preflight_hermes_command
from .log import configure_logging
from .models import ApprovalStatus, ConversationMapping
from .providers.agentmail import AgentMailProvider
from .providers.base import EmailProvider, RetryableProviderError
from .providers.composio_agentmail import ComposioAgentMailProvider
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
    init_db = commands.add_parser("init-db", help="Initialize the SQLite mapping store")
    init_db.add_argument(
        "--start-now",
        action="store_true",
        help="Seed missing inbound and sent cursors without importing history",
    )
    allowlist = commands.add_parser("allowlist", help="Manage exact sender authorization")
    allowlist_commands = allowlist.add_subparsers(dest="allowlist_command", required=True)
    allowlist_commands.add_parser("list", help="List authorized sender addresses")
    allowlist_add = allowlist_commands.add_parser("add", help="Authorize one exact address")
    allowlist_add.add_argument("address")
    allowlist_remove = allowlist_commands.add_parser("remove", help="Remove one exact address")
    allowlist_remove.add_argument("address")
    approvals = commands.add_parser(
        "approvals", help="Review quarantined requests that cannot auto-dispatch"
    )
    approval_commands = approvals.add_subparsers(dest="approvals_command", required=True)
    approval_list = approval_commands.add_parser("list", help="List pending requests")
    approval_list.add_argument("--all", action="store_true", help="Include closed requests")
    approval_resolve = approval_commands.add_parser(
        "resolve", help="Mark a manually handled request resolved"
    )
    approval_resolve.add_argument("approval_id", type=int)
    approval_reject = approval_commands.add_parser("reject", help="Reject a pending request")
    approval_reject.add_argument("approval_id", type=int)
    approval_purge = approval_commands.add_parser("purge", help="Delete old closed requests")
    approval_purge.add_argument("--closed-older-than-days", type=int, required=True)
    return parser


def _provider(settings: Settings) -> EmailProvider:
    if settings.provider == "agentmail":
        api_key, inbox_id = settings.require_agentmail()
        return AgentMailProvider(
            api_key=api_key,
            inbox_id=inbox_id,
            base_url=settings.agentmail_base_url,
            allow_insecure_local_http=settings.agentmail_allow_insecure_local_http,
        )
    if settings.provider == "composio-agentmail":
        api_key, connected_account_id, inbox_id = settings.require_composio_agentmail()
        return ComposioAgentMailProvider(
            api_key=api_key,
            connected_account_id=connected_account_id,
            inbox_id=inbox_id,
        )
    raise ConfigError(f"unsupported provider: {settings.provider}")


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
            settings.hermes_timeout,
            command_preflight=lambda: preflight_hermes_command(settings.hermes_command),
        ),
        send_replies=settings.send_replies,
        dry_run=settings.dry_run,
        reply_domains=settings.reply_domains,
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


def _run_poll_loop(
    service: BridgeService,
    *,
    continuous: bool,
    interval: float,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    failures = 0
    while True:
        try:
            summary = service.poll_once()
        except RetryableProviderError as exc:
            if not continuous:
                raise
            failures += 1
            delay = min(300.0, interval * (2 ** min(failures - 1, 8)))
            if exc.retry_after is not None:
                delay = max(delay, exc.retry_after)
            logger.warning(
                "provider retry scheduled",
                extra={"event": "provider_retry", "delay": delay},
            )
            sleep(delay)
            continue
        failures = 0
        print(json.dumps(asdict(summary)))
        if not continuous:
            return 1 if summary.failed else 0
        sleep(interval)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        settings = Settings.from_env()
        configure_logging(settings.log_level)
        with MappingStore(settings.db_path) as store:
            if args.command == "init-db":
                seeded = (
                    store.seed_poll_cursors(settings.logical_provider()) if args.start_now else ()
                )
                print(json.dumps({"db_path": str(settings.db_path), "seeded": seeded}))
                return 0
            if args.command == "allowlist":
                provider_name = settings.logical_provider()
                if args.allowlist_command == "add":
                    entry = store.add_allowed_address(provider_name, args.address)
                    print(json.dumps(asdict(entry), default=str))
                    return 0
                if args.allowlist_command == "remove":
                    print(
                        json.dumps(
                            {"removed": store.remove_allowed_address(provider_name, args.address)}
                        )
                    )
                    return 0
                print(
                    json.dumps(
                        [asdict(entry) for entry in store.list_allowed_addresses(provider_name)],
                        default=str,
                    )
                )
                return 0
            if args.command == "approvals":
                provider_name = settings.logical_provider()
                if args.approvals_command == "purge":
                    print(
                        json.dumps(
                            {
                                "purged": store.purge_closed_approvals(
                                    args.closed_older_than_days
                                )
                            }
                        )
                    )
                    return 0
                if args.approvals_command == "resolve":
                    status = ApprovalStatus.RESOLVED
                elif args.approvals_command == "reject":
                    status = ApprovalStatus.REJECTED
                else:
                    requests = store.list_approvals(
                        provider_name, include_closed=args.all
                    )
                    print(json.dumps([asdict(item) for item in requests], default=str))
                    return 0
                try:
                    request = store.set_approval_status(
                        provider_name, args.approval_id, status
                    )
                except KeyError as exc:
                    raise ConfigError(
                        f"pending approval {args.approval_id} does not exist"
                    ) from exc
                print(json.dumps(asdict(request), default=str))
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
                    queue_size=settings.webhook_queue_size,
                )
                return 0

            interval = settings.poll_interval if args.interval is None else args.interval
            if interval <= 0:
                raise ConfigError("poll interval must be positive")
            return _run_poll_loop(
                service,
                continuous=args.continuous,
                interval=interval,
            )
    except KeyboardInterrupt:
        logger.info("bridge stopped", extra={"event": "bridge_stopped"})
        return 130
    except (ConfigError, ValueError, OSError, RuntimeError) as exc:
        logger.error("bridge failed", extra={"event": "bridge_error", "reason": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
