"""Service-account identity and the user/agent -> service-account grants.

Security invariant 6: a caller may only execute through a service account when
an explicit, unrevoked grant exists.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..errors import ConflictError, NotFoundError
from ..models import IdentityType, Role, ServiceAccount, ServiceAccountGrant, utcnow


def create_service_account(
    db: DbSession,
    *,
    name: str,
    description: str | None = None,
    roles: list[str] | None = None,
) -> ServiceAccount:
    if get_service_account_by_name(db, name) is not None:
        raise ConflictError(f"service account already exists: {name}", code="sa_exists")
    sa = ServiceAccount(name=name, description=description)
    if roles:
        found = db.scalars(select(Role).where(Role.name.in_(roles))).all()
        missing = set(roles) - {r.name for r in found}
        if missing:
            raise NotFoundError(f"unknown roles: {sorted(missing)}", code="unknown_role")
        sa.roles = list(found)
    db.add(sa)
    db.flush()
    return sa


def get_service_account(db: DbSession, sa_id: str) -> ServiceAccount | None:
    return db.get(ServiceAccount, sa_id)


def get_service_account_by_name(db: DbSession, name: str) -> ServiceAccount | None:
    return db.scalar(select(ServiceAccount).where(ServiceAccount.name == name))


def resolve_service_account(db: DbSession, identifier: str) -> ServiceAccount | None:
    return get_service_account(db, identifier) or get_service_account_by_name(db, identifier)


def require_service_account(db: DbSession, identifier: str) -> ServiceAccount:
    sa = resolve_service_account(db, identifier)
    if sa is None:
        raise NotFoundError(
            f"unknown service account: {identifier}", code="unknown_service_account"
        )
    return sa


def list_service_accounts(db: DbSession) -> list[ServiceAccount]:
    return list(db.scalars(select(ServiceAccount).order_by(ServiceAccount.created_at)))


def grant_service_account(
    db: DbSession,
    *,
    grantee_type: IdentityType,
    grantee_id: str,
    service_account_id: str,
) -> ServiceAccountGrant:
    existing = _find_grant(
        db,
        grantee_type=grantee_type,
        grantee_id=grantee_id,
        service_account_id=service_account_id,
    )
    if existing is not None:
        existing.revoked_at = None
        db.flush()
        return existing
    grant = ServiceAccountGrant(
        grantee_type=grantee_type,
        grantee_id=grantee_id,
        service_account_id=service_account_id,
    )
    db.add(grant)
    db.flush()
    return grant


def revoke_service_account(
    db: DbSession, *, grantee_type: IdentityType, grantee_id: str, service_account_id: str
) -> None:
    grant = _find_grant(
        db,
        grantee_type=grantee_type,
        grantee_id=grantee_id,
        service_account_id=service_account_id,
    )
    if grant is not None:
        grant.revoked_at = utcnow()
        db.flush()


def _find_grant(
    db: DbSession, *, grantee_type: IdentityType, grantee_id: str, service_account_id: str
) -> ServiceAccountGrant | None:
    return db.scalar(
        select(ServiceAccountGrant).where(
            ServiceAccountGrant.grantee_type == grantee_type,
            ServiceAccountGrant.grantee_id == grantee_id,
            ServiceAccountGrant.service_account_id == service_account_id,
        )
    )


def may_use_service_account(
    db: DbSession, *, grantee_type: IdentityType, grantee_id: str, service_account_id: str
) -> bool:
    grant = _find_grant(
        db,
        grantee_type=grantee_type,
        grantee_id=grantee_id,
        service_account_id=service_account_id,
    )
    return grant is not None and grant.revoked_at is None


def list_grants_for(
    db: DbSession, *, grantee_type: IdentityType, grantee_id: str
) -> list[ServiceAccount]:
    rows = db.scalars(
        select(ServiceAccountGrant).where(
            ServiceAccountGrant.grantee_type == grantee_type,
            ServiceAccountGrant.grantee_id == grantee_id,
            ServiceAccountGrant.revoked_at.is_(None),
        )
    ).all()
    if not rows:
        return []
    ids = [row.service_account_id for row in rows]
    return list(db.scalars(select(ServiceAccount).where(ServiceAccount.id.in_(ids))))
