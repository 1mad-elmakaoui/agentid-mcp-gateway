"""Claims of a gateway-issued downstream credential.

A downstream MCP server sees exactly this much identity: who authorized the
call, which agent performed it, and which identity it executes as. It never
sees the caller's own gateway token, and never any credential of its own peers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(slots=True)
class GatewayClaims:
    #: Execution identity: the service account, user or agent the call runs as.
    subject: str
    subject_type: str
    audience: str
    issuer: str
    issued_at: datetime
    expires_at: datetime
    persona: str
    jti: str
    #: The agent that performed the call, when one was involved (``act.sub``).
    agent: str | None = None
    #: The human who authorized the call, when there was one.
    on_behalf_of: str | None = None
    service_account: str | None = None
    tool: str | None = None
    request_id: str | None = None
    scopes: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_autonomous(self) -> bool:
        return self.persona == "non-user"

    @property
    def human_user(self) -> str | None:
        """The human in the chain, or ``None`` for autonomous execution."""
        return self.on_behalf_of if self.subject_type != "user" else self.subject

    def identity_chain(self) -> str:
        parts = [p for p in (self.human_user, self.agent, self.service_account) if p]
        return " -> ".join(parts) if parts else self.subject

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> GatewayClaims:
        act = payload.get("act") or {}
        aud = payload.get("aud")
        if isinstance(aud, list):  # pragma: no cover - defensive
            aud = aud[0]
        scope = payload.get("scope") or ""
        return cls(
            subject=str(payload["sub"]),
            subject_type=str(payload.get("sub_type", "user")),
            audience=str(aud),
            issuer=str(payload.get("iss", "")),
            issued_at=datetime.fromtimestamp(int(payload["iat"]), tz=UTC),
            expires_at=datetime.fromtimestamp(int(payload["exp"]), tz=UTC),
            persona=str(payload.get("persona", "user")),
            jti=str(payload.get("jti", "")),
            agent=str(act["sub"]) if act.get("sub") else None,
            on_behalf_of=payload.get("on_behalf_of"),
            service_account=payload.get("execution_identity"),
            tool=payload.get("tool"),
            request_id=payload.get("rid"),
            scopes=tuple(scope.split()) if scope else (),
            raw=payload,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "subject_type": self.subject_type,
            "persona": self.persona,
            "agent": self.agent,
            "on_behalf_of": self.on_behalf_of,
            "service_account": self.service_account,
            "tool": self.tool,
            "request_id": self.request_id,
            "scopes": list(self.scopes),
            "identity_chain": self.identity_chain(),
        }
