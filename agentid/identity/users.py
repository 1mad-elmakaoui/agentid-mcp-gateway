"""User identity operations."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..errors import AuthenticationError, ConflictError, NotFoundError
from ..models import Role, User
from .secrets import hash_password, verify


def create_user(
    db: DbSession,
    *,
    email: str,
    password: str | None = None,
    display_name: str | None = None,
    roles: list[str] | None = None,
) -> User:
    email = email.strip().lower()
    if get_user_by_email(db, email) is not None:
        raise ConflictError(f"user already exists: {email}", code="user_exists")
    user = User(
        email=email,
        display_name=display_name,
        password_hash=hash_password(password) if password else None,
    )
    if roles:
        user.roles = _resolve_roles(db, roles)
    db.add(user)
    db.flush()
    return user


def _resolve_roles(db: DbSession, names: list[str]) -> list[Role]:
    found = db.scalars(select(Role).where(Role.name.in_(names))).all()
    missing = set(names) - {r.name for r in found}
    if missing:
        raise NotFoundError(f"unknown roles: {sorted(missing)}", code="unknown_role")
    return list(found)


def get_user(db: DbSession, user_id: str) -> User | None:
    return db.get(User, user_id)


def require_user(db: DbSession, user_id: str) -> User:
    user = get_user(db, user_id)
    if user is None:
        raise NotFoundError(f"unknown user: {user_id}", code="unknown_user")
    return user


def get_user_by_email(db: DbSession, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email.strip().lower()))


def list_users(db: DbSession) -> list[User]:
    return list(db.scalars(select(User).order_by(User.created_at)))


def authenticate_user(db: DbSession, *, email: str, password: str) -> User:
    """Verify a password login. Raises rather than returning ``None`` so the
    caller cannot accidentally treat a failure as success."""
    user = get_user_by_email(db, email)
    if user is None or not verify(password, user.password_hash):
        # Same error for unknown user and bad password: no account enumeration.
        raise AuthenticationError("invalid credentials", code="invalid_credentials")
    if not user.is_active:
        raise AuthenticationError("user is disabled", code="user_disabled")
    return user


def set_password(db: DbSession, user: User, password: str) -> User:
    user.password_hash = hash_password(password)
    db.flush()
    return user


def assign_roles(db: DbSession, user: User, role_names: list[str]) -> User:
    user.roles = _resolve_roles(db, role_names)
    db.flush()
    return user
