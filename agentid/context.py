"""The per-request identity context.

Built once by the authentication middleware and threaded through
authorization, credential resolution, the MCP proxy and audit so no component
has to re-derive identity (architecture §17).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .models import Persona


@dataclass(slots=True)
class RequestContext:
    request_id: str
    persona: Persona
    #: Human on whose behalf the request runs. ``None`` for autonomous calls.
    user_id: str | None = None
    #: The agent performing the request (``act.sub`` of a delegated token).
    agent_id: str | None = None
    #: Service account the downstream call executes as, once resolved.
    service_account_id: str | None = None
    session_id: str | None = None
    delegation_id: str | None = None
    token_id: str | None = None
    scopes: tuple[str, ...] = ()
    #: Populated by the routing layer before authorization.
    server: str | None = None
    tool: str | None = None
    resource: str | None = None
    client: str | None = None
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def is_user_persona(self) -> bool:
        return self.persona == Persona.USER

    @property
    def is_delegated(self) -> bool:
        """True when a human delegated to an agent (``sub`` + ``act``)."""
        return self.user_id is not None and self.agent_id is not None

    @property
    def execution_identity(self) -> str:
        """The identity the downstream request actually runs as."""
        if self.service_account_id:
            return self.service_account_id
        if self.user_id:
            return self.user_id
        if self.agent_id:
            return self.agent_id
        return "anonymous"

    def principal_description(self) -> str:
        parts = [f"persona={self.persona.value}"]
        if self.user_id:
            parts.append(f"user={self.user_id}")
        if self.agent_id:
            parts.append(f"agent={self.agent_id}")
        if self.service_account_id:
            parts.append(f"service_account={self.service_account_id}")
        return " ".join(parts)

    def audit_fields(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "service_account_id": self.service_account_id,
            "persona": self.persona,
            "execution_identity": self.execution_identity,
            "session_id": self.session_id,
            "server": self.server,
            "tool": self.tool,
            "resource": self.resource,
        }

    def with_tool(
        self, *, server: str | None, tool: str | None, resource: str | None = None
    ) -> RequestContext:
        self.server = server
        self.tool = tool
        if resource is not None:
            self.resource = resource
        return self
