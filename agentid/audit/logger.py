"""The audit logger used by the gateway."""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session as DbSession

from ..config import Settings, get_settings
from ..context import RequestContext
from .events import Action, AuditRecord, Outcome
from .storage import AuditSink, DatabaseSink

logger = logging.getLogger("agentid.audit")


class AuditLogger:
    """Writes each event to the database and (optionally) to stdout as JSON."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        sinks: list[AuditSink] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.sinks: list[AuditSink] = sinks if sinks is not None else [DatabaseSink()]

    def add_sink(self, sink: AuditSink) -> None:
        self.sinks.append(sink)

    def record(self, db: DbSession | None, record: AuditRecord) -> AuditRecord:
        for sink in self.sinks:
            sink.write(db, record)
        if self.settings.audit_stdout:
            logger.info("%s", json.dumps(record.to_dict(), default=str))
        return record

    def log(
        self,
        db: DbSession | None,
        ctx: RequestContext,
        *,
        action: str,
        decision: str,
        **kwargs: Any,
    ) -> AuditRecord:
        return self.record(
            db, AuditRecord.from_context(ctx, action=action, decision=decision, **kwargs)
        )

    # -- convenience wrappers -------------------------------------------
    def allow(self, db: DbSession | None, ctx: RequestContext, **kwargs: Any) -> AuditRecord:
        return self.log(db, ctx, action=Action.TOOL_CALL, decision=Outcome.ALLOW, **kwargs)

    def deny(self, db: DbSession | None, ctx: RequestContext, **kwargs: Any) -> AuditRecord:
        return self.log(db, ctx, action=Action.TOOL_CALL, decision=Outcome.DENY, **kwargs)

    def error(self, db: DbSession | None, ctx: RequestContext, **kwargs: Any) -> AuditRecord:
        return self.log(db, ctx, action=Action.TOOL_CALL, decision=Outcome.ERROR, **kwargs)


_default_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    global _default_logger
    if _default_logger is None:
        _default_logger = AuditLogger()
    return _default_logger


def set_audit_logger(audit_logger: AuditLogger | None) -> None:
    global _default_logger
    _default_logger = audit_logger
