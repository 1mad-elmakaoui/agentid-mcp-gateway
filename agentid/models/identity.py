"""Identity entities: users, agents and service accounts.

These three types are deliberately separate tables. AgentID never lets one
identity type silently become another (security invariants 2 and 3), so there
is no shared "principal" row they could be coerced through.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, EnumType, TimestampMixin, new_id


class Persona(StrEnum):
    """The two caller personas. This distinction is a security boundary."""

    USER = "user"
    NON_USER = "non-user"


class IdentityType(StrEnum):
    USER = "user"
    AGENT = "agent"
    SERVICE_ACCOUNT = "service_account"
    #: The gateway itself, used as the owner of server-default credentials.
    GATEWAY = "gateway"


class AgentKind(StrEnum):
    #: Operates on behalf of a human; requires a delegating user.
    DELEGATED = "delegated"
    #: Runs without a human in the chain; must execute via a service account.
    AUTONOMOUS = "autonomous"


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("user"))
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    display_name: Mapped[str | None] = mapped_column(String(200))
    password_hash: Mapped[str | None] = mapped_column(String(512))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    roles: Mapped[list[Role]] = relationship(  # noqa: F821
        secondary="user_roles", back_populates="users", lazy="selectin"
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<User {self.id} {self.email}>"


class Agent(TimestampMixin, Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("agent"))
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    kind: Mapped[AgentKind] = mapped_column(
        EnumType(AgentKind), default=AgentKind.DELEGATED, nullable=False
    )
    #: Optional human owner. Ownership is *not* authorization: an owner still
    #: needs an explicit user->agent grant to delegate to this agent.
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    roles: Mapped[list[Role]] = relationship(  # noqa: F821
        secondary="agent_roles", back_populates="agents", lazy="selectin"
    )

    @property
    def is_autonomous(self) -> bool:
        return self.kind == AgentKind.AUTONOMOUS

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Agent {self.id} {self.name}>"


class ServiceAccount(TimestampMixin, Base):
    __tablename__ = "service_accounts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("sa"))
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    roles: Mapped[list[Role]] = relationship(  # noqa: F821
        secondary="service_account_roles", back_populates="service_accounts", lazy="selectin"
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ServiceAccount {self.id} {self.name}>"


class UserAgentGrant(TimestampMixin, Base):
    """A user explicitly authorizes an agent to act on their behalf."""

    __tablename__ = "user_agent_grants"
    __table_args__ = (UniqueConstraint("user_id", "agent_id"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("uag"))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), nullable=False, index=True)
    #: Optional narrowing of what the agent may do for this user. Empty means
    #: "everything the intersection of user and agent permissions allows".
    scopes: Mapped[str | None] = mapped_column(Text)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ServiceAccountGrant(TimestampMixin, Base):
    """Authorization to execute *through* a service account.

    The grantee is a user or an agent. Without a matching, unrevoked row the
    gateway refuses to resolve the service account's credential (invariant 6).
    """

    __tablename__ = "service_account_grants"
    __table_args__ = (UniqueConstraint("grantee_type", "grantee_id", "service_account_id"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("sag"))
    grantee_type: Mapped[IdentityType] = mapped_column(EnumType(IdentityType), nullable=False)
    grantee_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    service_account_id: Mapped[str] = mapped_column(
        ForeignKey("service_accounts.id"), nullable=False, index=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
