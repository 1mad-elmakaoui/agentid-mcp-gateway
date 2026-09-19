"""Audit persistence and querying."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..models import AuditEvent
from .events import AuditRecord


class AuditSink(Protocol):  # pragma: no cover - structural type
    def write(self, db: DbSession | None, record: AuditRecord) -> None: ...


class DatabaseSink:
    """Appends events to the ``audit_events`` table."""

    def write(self, db: DbSession | None, record: AuditRecord) -> None:
        if db is None:  # pragma: no cover - defensive
            return
        db.add(record.to_model())
        db.flush()


class MemorySink:
    """Collects events in memory (tests, dry runs)."""

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def write(self, _db: DbSession | None, record: AuditRecord) -> None:
        self.records.append(record)

    def clear(self) -> None:
        self.records.clear()


def query_events(
    db: DbSession,
    *,
    user_id: str | None = None,
    agent_id: str | None = None,
    tool: str | None = None,
    server: str | None = None,
    decision: str | None = None,
    action: str | None = None,
    request_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditEvent]:
    stmt = select(AuditEvent).order_by(AuditEvent.timestamp.desc(), AuditEvent.id.desc())
    if user_id:
        stmt = stmt.where(AuditEvent.user_id == user_id)
    if agent_id:
        stmt = stmt.where(AuditEvent.agent_id == agent_id)
    if tool:
        stmt = stmt.where(AuditEvent.tool == tool)
    if server:
        stmt = stmt.where(AuditEvent.server == server)
    if decision:
        stmt = stmt.where(AuditEvent.decision == decision)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if request_id:
        stmt = stmt.where(AuditEvent.request_id == request_id)
    if since:
        stmt = stmt.where(AuditEvent.timestamp >= since)
    if until:
        stmt = stmt.where(AuditEvent.timestamp <= until)
    return list(db.scalars(stmt.limit(limit).offset(offset)))


def event_to_dict(event: AuditEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "action": event.action,
        "user_id": event.user_id,
        "agent_id": event.agent_id,
        "service_account_id": event.service_account_id,
        "persona": event.persona.value if event.persona else None,
        "execution_identity": event.execution_identity,
        "session_id": event.session_id,
        "request_id": event.request_id,
        "server": event.server,
        "tool": event.tool,
        "resource": event.resource,
        "decision": event.decision,
        "reason": event.reason,
        "policy": event.policy,
        "status_code": event.status_code,
        "latency_ms": event.latency_ms,
        "error": event.error,
        "details": event.details or {},
    }
