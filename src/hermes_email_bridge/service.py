"""Bridge orchestration independent of provider and Hermes implementations."""

from __future__ import annotations

import logging

from .models import NormalizedEmail, PollSummary, ResolutionStatus
from .providers.base import EmailProvider
from .runner import HermesRunner
from .store import MappingStore

logger = logging.getLogger(__name__)


class BridgeService:
    def __init__(
        self,
        *,
        provider: EmailProvider,
        store: MappingStore,
        runner: HermesRunner,
        send_replies: bool = False,
        dry_run: bool = True,
        store_raw: bool = False,
        raw_retention_days: int = 30,
        allow_subject_resume: bool = False,
    ) -> None:
        self.provider = provider
        self.store = store
        self.runner = runner
        self.send_replies = send_replies
        self.dry_run = dry_run
        self.store_raw = store_raw
        self.raw_retention_days = raw_retention_days
        self.allow_subject_resume = allow_subject_resume
        self.store.purge_raw(raw_retention_days)

    def handle(self, message: NormalizedEmail) -> str:
        context: dict[str, object] = {
            "provider": message.provider,
            "provider_message_id": message.provider_message_id,
            "thread_id": message.thread_id,
        }
        logger.info("message received", extra={"event": "message_received", **context})
        if self.store.is_processed(message.provider, message.provider_message_id):
            logger.info(
                "message skipped",
                extra={"event": "message_skipped", "reason": "already_processed", **context},
            )
            return "skipped"

        logger.info(
            "message parsed",
            extra={
                "event": "message_parsed",
                "attachment_count": len(message.attachments),
                **context,
            },
        )
        resolution = self.store.resolve(message, allow_subject_resume=self.allow_subject_resume)
        if resolution.status is ResolutionStatus.DENIED:
            logger.warning(
                "message denied",
                extra={
                    "event": "message_denied",
                    "reason": resolution.matched_by,
                    "sender_authentication": message.sender_authentication,
                    **context,
                },
            )
            self.store.mark_processed(
                message,
                "authorization_denied",
                store_raw=False,
                raw_retention_days=self.raw_retention_days,
            )
            return "skipped"

        mapping = resolution.mapping
        logger.info(
            "mapping found" if mapping else "mapping not found",
            extra={
                "event": "mapping_found" if mapping else "mapping_not_found",
                "matched_by": resolution.matched_by,
                "hermes_session": mapping.hermes_session if mapping else None,
                **context,
            },
        )

        result = self.runner.run(message, mapping)
        logger.info(
            "Hermes invoked",
            extra={
                "event": "hermes_invoked",
                "hermes_session": result.session_id,
                **context,
            },
        )

        if mapping:
            self.store.add_message_link(message.provider, message.provider_message_id, mapping.id)
        elif result.session_id:
            mapping = self.store.add_mapping(
                provider=message.provider,
                hermes_session=result.session_id,
                provider_thread_id=message.thread_id,
                subject=message.subject,
                participant_email=message.from_email,
                message_ids=(message.provider_message_id,),
            )

        if not self.send_replies:
            outcome = "reply_disabled"
            self._log_reply_skipped("send_disabled", context)
        elif self.dry_run:
            outcome = "reply_dry_run"
            self._log_reply_skipped("dry_run", context)
        elif not result.reply:
            outcome = "reply_empty"
            self._log_reply_skipped("empty_hermes_response", context)
        else:
            try:
                reply_id = self.provider.reply(message, result.reply)
            except Exception:
                self.store.mark_processed(
                    message,
                    "reply_failed",
                    store_raw=self.store_raw,
                    raw_retention_days=self.raw_retention_days,
                )
                logger.exception("reply failed", extra={"event": "reply_failed", **context})
                raise
            if mapping:
                self.store.add_message_link(message.provider, reply_id, mapping.id)
            outcome = "reply_sent"
            logger.info(
                "reply sent",
                extra={"event": "reply_sent", "reply_message_id": reply_id, **context},
            )

        self.store.mark_processed(
            message,
            outcome,
            store_raw=self.store_raw,
            raw_retention_days=self.raw_retention_days,
        )
        return "processed"

    @staticmethod
    def _log_reply_skipped(reason: str, context: dict[str, object]) -> None:
        logger.info(
            "reply skipped",
            extra={"event": "reply_skipped", "reason": reason, **context},
        )

    def poll_once(self) -> PollSummary:
        cursor = self.store.get_cursor(self.provider.name)
        result = self.provider.poll(cursor)
        processed = skipped = failed = 0
        for message in result.messages:
            try:
                outcome = self.handle(message)
            except Exception:
                failed += 1
                logger.exception(
                    "message processing failed",
                    extra={
                        "event": "message_error",
                        "provider": message.provider,
                        "provider_message_id": message.provider_message_id,
                    },
                )
            else:
                if outcome == "skipped":
                    skipped += 1
                else:
                    processed += 1
        if not failed and result.cursor:
            self.store.set_cursor(self.provider.name, result.cursor)
        return PollSummary(len(result.messages), processed, skipped, failed)
