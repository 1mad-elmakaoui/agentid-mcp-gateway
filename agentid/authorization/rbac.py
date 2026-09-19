"""Role-based permission resolution.

Turns the role bindings stored in the database into :class:`PermissionSet`
objects for users, agents and service accounts.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..models import Agent, Effect, Permission, Role, RolePermission, ServiceAccount, User
from .permissions import PermissionSet


def _from_roles(roles: list[Role]) -> PermissionSet:
    result = PermissionSet(sources=tuple(role.name for role in roles))
    for role in roles:
        for entry in role.entries:
            if entry.effect == Effect.DENY:
                result.deny.add(entry.permission.name)
            else:
                result.allow.add(entry.permission.name)
    return result


def permissions_for_user(_db: DbSession, user: User) -> PermissionSet:
    return _from_roles(list(user.roles))


def permissions_for_agent(_db: DbSession, agent: Agent) -> PermissionSet:
    return _from_roles(list(agent.roles))


def permissions_for_service_account(_db: DbSession, sa: ServiceAccount) -> PermissionSet:
    return _from_roles(list(sa.roles))


def all_permission_names(db: DbSession) -> set[str]:
    return set(db.scalars(select(Permission.name)))


# -- administration ------------------------------------------------------


def upsert_permission(db: DbSession, name: str, description: str | None = None) -> Permission:
    existing = db.scalar(select(Permission).where(Permission.name == name))
    if existing is not None:
        if description and not existing.description:
            existing.description = description
        return existing
    permission = Permission(name=name, description=description)
    db.add(permission)
    db.flush()
    return permission


def upsert_role(
    db: DbSession,
    name: str,
    *,
    allow: list[str] | None = None,
    deny: list[str] | None = None,
    description: str | None = None,
    replace: bool = True,
) -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:
        role = Role(name=name, description=description)
        db.add(role)
        db.flush()
    elif description:
        role.description = description

    if replace:
        for entry in list(role.entries):
            db.delete(entry)
        db.flush()
        role.entries = []

    existing = {(e.permission.name, e.effect) for e in role.entries}
    for effect, names in ((Effect.ALLOW, allow or []), (Effect.DENY, deny or [])):
        for perm_name in names:
            if (perm_name, effect) in existing:
                continue
            permission = upsert_permission(db, perm_name)
            db.add(
                RolePermission(role_id=role.id, permission_id=permission.id, effect=effect)
            )
    db.flush()
    db.refresh(role)
    return role


def get_role(db: DbSession, name: str) -> Role | None:
    return db.scalar(select(Role).where(Role.name == name))


def list_roles(db: DbSession) -> list[Role]:
    return list(db.scalars(select(Role).order_by(Role.name)))
