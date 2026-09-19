"""Append-only audit events."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, EnumType, new_id, utcnow
from .identity import Persona


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("evt"))
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    #: e.g. ``mcp.call``, ``auth.token``, ``auth.delegate``.
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    user_id: Mapped[str | None] = mapped_column(String(64), index=True)
    agent_id: Mapped[str | None] = mapped_column(String(64), index=True)
    service_account_id: Mapped[str | None] = mapped_column(String(64))
    persona: Mapped[Persona | None] = mapped_column(EnumType(Persona))
    #: The identity the downstream request actually executed as.
    execution_identity: Mapped[str | None] = mapped_column(String(64))
    session_id: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(64), index=True)
    server: Mapped[str | None] = mapped_column(String(200))
    tool: Mapped[str | None] = mapped_column(String(400), index=True)
    resource: Mapped[str | None] = mapped_column(String(500))
    decision: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    reason: Mapped[str | None] = mapped_column(String(200))
    policy: Mapped[str | None] = mapped_column(String(200))
    status_code: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AuditEvent {self.action} {self.decision} tool={self.tool}>"
