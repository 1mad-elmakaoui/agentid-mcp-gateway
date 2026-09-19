"""Structured authorization decisions.

Every check returns a :class:`Decision` rather than a bare boolean so the audit
trail records *why* a request was allowed or denied.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class Reason(StrEnum):
    ALLOWED = "allowed"
    UNAUTHENTICATED = "unauthenticated"
    MISSING_PERMISSION = "missing_permission"
    EXPLICIT_DENY = "explicit_deny"
    AGENT_NOT_PERMITTED = "agent_not_permitted"
    EXCEEDS_USER_PERMISSIONS = "exceeds_user_permissions"
    SERVICE_ACCOUNT_NOT_AUTHORIZED = "service_account_not_authorized"
    SERVICE_ACCOUNT_NOT_PERMITTED = "service_account_not_permitted"
    SERVICE_ACCOUNT_REQUIRED = "service_account_required"
    DELEGATION_REQUIRED = "delegation_required"
    DELEGATION_INVALID = "invalid_delegation"
    PERSONA_VIOLATION = "persona_violation"
    IDENTITY_DISABLED = "identity_disabled"
    UNKNOWN_TOOL = "unknown_tool"
    SERVER_DISABLED = "server_disabled"
    TOOL_DISABLED = "tool_disabled"
    MISSING_SCOPE = "missing_scope"


@dataclass(slots=True)
class Decision:
    effect: Effect
    reason: Reason
    #: Name of the policy/role that produced the decision, when identifiable.
    policy: str | None = None
    permission: str | None = None
    tool: str | None = None
    server: str | None = None
    #: Identity the downstream call must execute as, when the decision allows.
    execution_identity: str | None = None
    service_account_id: str | None = None
    message: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.effect == Effect.ALLOW

    @classmethod
    def allow(cls, **kwargs: Any) -> Decision:
        kwargs.setdefault("reason", Reason.ALLOWED)
        return cls(effect=Effect.ALLOW, **kwargs)

    @classmethod
    def deny(cls, reason: Reason, **kwargs: Any) -> Decision:
        return cls(effect=Effect.DENY, reason=reason, **kwargs)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "decision": self.effect.value,
            "reason": self.reason.value,
        }
        for key in ("policy", "permission", "tool", "server", "execution_identity", "message"):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        if self.details:
            payload["details"] = self.details
        return payload
