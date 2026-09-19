"""RBAC entities: roles, permissions and their bindings.

A role carries *allow* and *deny* entries, mirroring the policy documents in
``docs/authorization.md``. Deny always wins over allow.
"""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import Column, ForeignKey, String, Table, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, EnumType, TimestampMixin, new_id


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", ForeignKey("users.id"), primary_key=True),
    Column("role_id", ForeignKey("roles.id"), primary_key=True),
)

agent_roles = Table(
    "agent_roles",
    Base.metadata,
    Column("agent_id", ForeignKey("agents.id"), primary_key=True),
    Column("role_id", ForeignKey("roles.id"), primary_key=True),
)

service_account_roles = Table(
    "service_account_roles",
    Base.metadata,
    Column("service_account_id", ForeignKey("service_accounts.id"), primary_key=True),
    Column("role_id", ForeignKey("roles.id"), primary_key=True),
)


class Permission(TimestampMixin, Base):
    """A permission name such as ``github.create_issue`` or ``github.*``."""

    __tablename__ = "permissions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("perm"))
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Permission {self.name}>"


class RolePermission(TimestampMixin, Base):
    __tablename__ = "role_permissions"
    __table_args__ = (UniqueConstraint("role_id", "permission_id", "effect"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("rp"))
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"), nullable=False, index=True)
    permission_id: Mapped[str] = mapped_column(ForeignKey("permissions.id"), nullable=False)
    effect: Mapped[Effect] = mapped_column(
        EnumType(Effect, 16), default=Effect.ALLOW, nullable=False
    )

    permission: Mapped[Permission] = relationship(lazy="selectin")


class Role(TimestampMixin, Base):
    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("role"))
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)

    entries: Mapped[list[RolePermission]] = relationship(
        lazy="selectin", cascade="all, delete-orphan"
    )
    users: Mapped[list[User]] = relationship(  # noqa: F821
        secondary=user_roles, back_populates="roles"
    )
    agents: Mapped[list[Agent]] = relationship(  # noqa: F821
        secondary=agent_roles, back_populates="roles"
    )
    service_accounts: Mapped[list[ServiceAccount]] = relationship(  # noqa: F821
        secondary=service_account_roles, back_populates="roles"
    )

    def allowed(self) -> set[str]:
        return {e.permission.name for e in self.entries if e.effect == Effect.ALLOW}

    def denied(self) -> set[str]:
        return {e.permission.name for e in self.entries if e.effect == Effect.DENY}

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Role {self.name}>"
