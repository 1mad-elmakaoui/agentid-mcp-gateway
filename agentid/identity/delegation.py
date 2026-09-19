"""User -> agent delegation (architecture §10, RFC 8693 style).

A delegated token answers two questions at once:

* who authorized the operation? -> ``sub``
* who actually performed it?    -> ``act.sub``

Both are preserved through authorization, the proxy and the audit trail.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..config import Settings, get_settings
from ..errors import DelegationError, PersonaViolation
from ..models import Agent, AgentKind, Delegation, Persona, User, as_aware, utcnow
from .agents import require_agent, user_may_delegate_to
from .tokens import TokenService


@dataclass(slots=True)
class DelegationResult:
    token: str
    delegation: Delegation
    expires_at: datetime
    agent: Agent


def delegate(
    db: DbSession,
    *,
    user: User,
    agent_identifier: str,
    session_id: str | None = None,
    scopes: tuple[str, ...] | list[str] = ("mcp:tools",),
    ttl_seconds: int | None = None,
    tokens: TokenService | None = None,
    settings: Settings | None = None,
) -> DelegationResult:
    """Exchange a user identity for a token the agent may present.

    Raises :class:`DelegationError` when the user has not authorized the agent,
    and :class:`PersonaViolation` when the target agent is autonomous — an
    autonomous agent runs under its own identity and must never pick up a
    human's.
    """
    settings = settings or get_settings()
    tokens = tokens or TokenService(settings)

    agent = require_agent(db, agent_identifier)
    if not agent.is_active:
        raise DelegationError(f"agent is disabled: {agent.name}", code="agent_disabled")
    if agent.kind == AgentKind.AUTONOMOUS:
        raise PersonaViolation(
            f"autonomous agent {agent.name} cannot act for a user",
            code="autonomous_agent_delegation",
            agent=agent.name,
        )
    if not user_may_delegate_to(db, user_id=user.id, agent_id=agent.id):
        raise DelegationError(
            f"user {user.id} has not authorized agent {agent.name}",
            code="delegation_not_granted",
            agent=agent.name,
        )

    ttl = ttl_seconds or settings.delegated_token_ttl_seconds
    expires_at = utcnow() + timedelta(seconds=ttl)
    scope_str = " ".join(scopes) if scopes else None

    record = Delegation(
        jti="",  # filled below, once the token is signed
        user_id=user.id,
        agent_id=agent.id,
        session_id=session_id,
        scope=scope_str,
        expires_at=expires_at,
    )
    db.add(record)
    db.flush()

    token, claims = tokens.issue_delegated_token(
        user_id=user.id,
        agent_id=agent.id,
        session_id=session_id,
        delegation_id=record.id,
        scopes=scopes,
        ttl_seconds=ttl,
    )
    record.jti = claims.jti
    db.flush()
    return DelegationResult(
        token=token, delegation=record, expires_at=expires_at, agent=agent
    )


def get_delegation(db: DbSession, delegation_id: str) -> Delegation | None:
    return db.get(Delegation, delegation_id)


def require_active_delegation(db: DbSession, delegation_id: str) -> Delegation:
    record = get_delegation(db, delegation_id)
    if record is None:
        raise DelegationError("unknown delegation", code="unknown_delegation")
    if record.revoked:
        raise DelegationError("delegation revoked", code="delegation_revoked")
    expires = as_aware(record.expires_at)
    if expires is None or expires <= utcnow():
        raise DelegationError("delegation expired", code="delegation_expired")
    return record


def revoke_delegation(db: DbSession, delegation_id: str) -> None:
    record = get_delegation(db, delegation_id)
    if record is not None and not record.revoked:
        record.revoked = True
        db.flush()


def revoke_delegations_for_user(db: DbSession, user_id: str) -> int:
    rows = db.scalars(
        select(Delegation).where(Delegation.user_id == user_id, Delegation.revoked.is_(False))
    ).all()
    for row in rows:
        row.revoked = True
    db.flush()
    return len(rows)


def describe_chain(
    *, user_id: str | None, agent_id: str | None, service_account_id: str | None
) -> str:
    """Render the delegation chain for logs and demos: ``user -> agent -> sa``."""
    parts = [p for p in (user_id, agent_id, service_account_id) if p]
    return " -> ".join(parts) if parts else "anonymous"


def persona_for(*, user_id: str | None, agent: Agent | None) -> Persona:
    """Derive the persona. An agent alone is never a user persona."""
    if user_id:
        return Persona.USER
    return Persona.NON_USER
