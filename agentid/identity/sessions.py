"""Session lifecycle."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..config import Settings, get_settings
from ..errors import AuthenticationError
from ..models import IdentityType, Persona, Session, utcnow


def create_session(
    db: DbSession,
    *,
    subject_type: IdentityType,
    subject_id: str,
    persona: Persona,
    agent_id: str | None = None,
    client: str | None = None,
    ttl_seconds: int | None = None,
    settings: Settings | None = None,
) -> Session:
    settings = settings or get_settings()
    ttl = ttl_seconds or settings.session_ttl_seconds
    session = Session(
        subject_type=subject_type,
        subject_id=subject_id,
        persona=persona,
        agent_id=agent_id,
        client=client,
        expires_at=utcnow() + timedelta(seconds=ttl),
    )
    db.add(session)
    db.flush()
    return session


def get_session(db: DbSession, session_id: str) -> Session | None:
    return db.get(Session, session_id)


def require_active_session(db: DbSession, session_id: str) -> Session:
    session = get_session(db, session_id)
    if session is None:
        raise AuthenticationError("unknown session", code="unknown_session")
    if not session.is_active:
        raise AuthenticationError("session is no longer active", code="session_inactive")
    return session


def revoke_session(db: DbSession, session_id: str) -> None:
    session = get_session(db, session_id)
    if session is not None and session.revoked_at is None:
        session.revoked_at = utcnow()
        db.flush()


def revoke_sessions_for(db: DbSession, *, subject_id: str) -> int:
    rows = db.scalars(
        select(Session).where(Session.subject_id == subject_id, Session.revoked_at.is_(None))
    ).all()
    now = utcnow()
    for row in rows:
        row.revoked_at = now
    db.flush()
    return len(rows)


def purge_expired(db: DbSession) -> int:
    rows = db.scalars(select(Session).where(Session.expires_at < utcnow())).all()
    for row in rows:
        db.delete(row)
    db.flush()
    return len(rows)
