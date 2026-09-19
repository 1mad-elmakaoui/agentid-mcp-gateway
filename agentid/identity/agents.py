"""Agent identity operations and user -> agent delegation grants."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..errors import ConflictError, NotFoundError
from ..models import Agent, AgentKind, Role, UserAgentGrant, utcnow


def create_agent(
    db: DbSession,
    *,
    name: str,
    kind: AgentKind = AgentKind.DELEGATED,
    description: str | None = None,
    owner_user_id: str | None = None,
    roles: list[str] | None = None,
) -> Agent:
    if get_agent_by_name(db, name) is not None:
        raise ConflictError(f"agent already exists: {name}", code="agent_exists")
    agent = Agent(
        name=name, kind=kind, description=description, owner_user_id=owner_user_id
    )
    if roles:
        found = db.scalars(select(Role).where(Role.name.in_(roles))).all()
        missing = set(roles) - {r.name for r in found}
        if missing:
            raise NotFoundError(f"unknown roles: {sorted(missing)}", code="unknown_role")
        agent.roles = list(found)
    db.add(agent)
    db.flush()
    return agent


def get_agent(db: DbSession, agent_id: str) -> Agent | None:
    return db.get(Agent, agent_id)


def get_agent_by_name(db: DbSession, name: str) -> Agent | None:
    return db.scalar(select(Agent).where(Agent.name == name))


def resolve_agent(db: DbSession, identifier: str) -> Agent | None:
    """Look an agent up by id or by name (clients use either)."""
    return get_agent(db, identifier) or get_agent_by_name(db, identifier)


def require_agent(db: DbSession, identifier: str) -> Agent:
    agent = resolve_agent(db, identifier)
    if agent is None:
        raise NotFoundError(f"unknown agent: {identifier}", code="unknown_agent")
    return agent


def list_agents(db: DbSession) -> list[Agent]:
    return list(db.scalars(select(Agent).order_by(Agent.created_at)))


def grant_agent_to_user(
    db: DbSession, *, user_id: str, agent_id: str, scopes: str | None = None
) -> UserAgentGrant:
    existing = _find_grant(db, user_id=user_id, agent_id=agent_id)
    if existing is not None:
        existing.revoked_at = None
        existing.scopes = scopes
        db.flush()
        return existing
    grant = UserAgentGrant(user_id=user_id, agent_id=agent_id, scopes=scopes)
    db.add(grant)
    db.flush()
    return grant


def revoke_agent_from_user(db: DbSession, *, user_id: str, agent_id: str) -> None:
    grant = _find_grant(db, user_id=user_id, agent_id=agent_id)
    if grant is not None:
        grant.revoked_at = utcnow()
        db.flush()


def _find_grant(db: DbSession, *, user_id: str, agent_id: str) -> UserAgentGrant | None:
    return db.scalar(
        select(UserAgentGrant).where(
            UserAgentGrant.user_id == user_id, UserAgentGrant.agent_id == agent_id
        )
    )


def user_may_delegate_to(db: DbSession, *, user_id: str, agent_id: str) -> bool:
    """Delegation requires an explicit, unrevoked grant.

    Owning an agent is not enough: ownership is a management relationship, not
    an authorization one.
    """
    grant = _find_grant(db, user_id=user_id, agent_id=agent_id)
    return grant is not None and grant.revoked_at is None


def list_user_agents(db: DbSession, user_id: str) -> list[Agent]:
    rows = db.scalars(
        select(UserAgentGrant).where(
            UserAgentGrant.user_id == user_id, UserAgentGrant.revoked_at.is_(None)
        )
    ).all()
    if not rows:
        return []
    ids = [row.agent_id for row in rows]
    return list(db.scalars(select(Agent).where(Agent.id.in_(ids))))
