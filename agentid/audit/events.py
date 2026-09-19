"""Audit event construction.

Every security-relevant operation produces one event (invariant 8). Events
carry the full identity chain — human user, acting agent, execution identity —
so the trail answers *who authorized this* and *who performed it*, not just one
of the two.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..context import RequestContext
from ..models import AuditEvent, Persona, utcnow


class Action:
    AUTH_TOKEN = "auth.token"
    AUTH_API_KEY = "auth.api_key"
    AUTH_FAILED = "auth.failed"
    AUTH_DELEGATE = "auth.delegate"
    SESSION_REVOKE = "auth.session.revoke"
    TOOL_DISCOVER = "mcp.discover"
    TOOL_CALL = "mcp.call"
    CREDENTIAL_RESOLVE = "credential.resolve"
    ADMIN_CHANGE = "admin.change"


class Outcome:
    ALLOW = "allow"
    DENY = "deny"
    ERROR = "error"


#: Keys that must never reach the audit store, however they were nested.
REDACTED_KEYS = frozenset(
    {
        "authorization",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "token",
        "secret",
        "password",
        "client_secret",
        "credential",
        "ciphertext",
        "x-downstream-api-key",
        "x-downstream-authorization",
    }
)

REDACTED = "***redacted***"


def redact(value: Any, *, _depth: int = 0) -> Any:
    """Recursively strip secret-looking values (credential tests depend on this)."""
    if _depth > 6:
        return REDACTED
    if isinstance(value, dict):
        return {
            k: (REDACTED if str(k).lower() in REDACTED_KEYS else redact(v, _depth=_depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v, _depth=_depth + 1) for v in value]
    return value


@dataclass(slots=True)
class AuditRecord:
    """A pending audit event, before it is persisted."""

    action: str
    decision: str
    timestamp: datetime = field(default_factory=utcnow)
    user_id: str | None = None
    agent_id: str | None = None
    service_account_id: str | None = None
    persona: Persona | None = None
    execution_identity: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    server: str | None = None
    tool: str | None = None
    resource: str | None = None
    reason: str | None = None
    policy: str | None = None
    status_code: int | None = None
    latency_ms: int | None = None
    error: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_context(
        cls, ctx: RequestContext, *, action: str, decision: str, **kwargs: Any
    ) -> AuditRecord:
        fields = ctx.audit_fields()
        fields.pop("persona", None)
        merged: dict[str, Any] = {
            **fields,
            "persona": ctx.persona,
            "action": action,
            "decision": decision,
        }
        merged.update({k: v for k, v in kwargs.items() if v is not None})
        details = redact(merged.pop("details", {}) or {})
        return cls(details=details, **merged)

    def to_model(self) -> AuditEvent:
        return AuditEvent(
            timestamp=self.timestamp,
            action=self.action,
            user_id=self.user_id,
            agent_id=self.agent_id,
            service_account_id=self.service_account_id,
            persona=self.persona,
            execution_identity=self.execution_identity,
            session_id=self.session_id,
            request_id=self.request_id,
            server=self.server,
            tool=self.tool,
            resource=self.resource,
            decision=self.decision,
            reason=self.reason,
            policy=self.policy,
            status_code=self.status_code,
            latency_ms=self.latency_ms,
            error=self.error,
            details=redact(self.details or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "service_account_id": self.service_account_id,
            "persona": self.persona.value if self.persona else None,
            "execution_identity": self.execution_identity,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "server": self.server,
            "tool": self.tool,
            "resource": self.resource,
            "decision": self.decision,
            "reason": self.reason,
            "policy": self.policy,
            "status_code": self.status_code,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "details": redact(self.details or {}),
        }
