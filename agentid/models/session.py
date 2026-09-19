"""Sessions, API keys and delegation records."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, EnumType, TimestampMixin, as_aware, new_id, utcnow
from .identity import IdentityType, Persona


class Session(TimestampMixin, Base):
    """A authenticated session for a user, agent or service account."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("sess"))
    subject_type: Mapped[IdentityType] = mapped_column(EnumType(IdentityType), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    persona: Mapped[Persona] = mapped_column(EnumType(Persona), nullable=False)
    #: Set when the session was created for an agent acting for a user.
    agent_id: Mapped[str | None] = mapped_column(ForeignKey("agents.id"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    client: Mapped[str | None] = mapped_column(String(200))

    @property
    def is_active(self) -> bool:
        if self.revoked_at is not None:
            return False
        expires = as_aware(self.expires_at)
        return expires is not None and expires > utcnow()


class ApiKey(TimestampMixin, Base):
    """A machine credential for agents and service accounts.

    Only the hash of the secret is stored; the plaintext is returned exactly
    once, at creation time.
    """

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("akey"))
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    #: Lookup hint stored in clear so verification is a single indexed read.
    key_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    secret_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    owner_type: Mapped[IdentityType] = mapped_column(EnumType(IdentityType), nullable=False)
    owner_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @property
    def is_active(self) -> bool:
        if self.revoked_at is not None:
            return False
        expires = as_aware(self.expires_at)
        return expires is None or expires > utcnow()


class Delegation(TimestampMixin, Base):
    """A record of an issued delegated token (``sub`` = user, ``act`` = agent)."""

    __tablename__ = "delegations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("dlg"))
    jti: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), nullable=False, index=True)
    session_id: Mapped[str | None] = mapped_column(ForeignKey("sessions.id"))
    scope: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    @property
    def is_active(self) -> bool:
        expires = as_aware(self.expires_at)
        return not self.revoked and expires is not None and expires > utcnow()
