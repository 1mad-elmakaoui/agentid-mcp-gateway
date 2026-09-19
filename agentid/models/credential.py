"""Stored downstream credentials.

Secret material is encrypted at rest and never leaves the gateway process in
plaintext (security invariant 7). The ORM object exposes only the ciphertext;
decryption lives in :mod:`agentid.credentials.vault`.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, EnumType, TimestampMixin, as_aware, new_id, utcnow
from .identity import IdentityType
from .registry import CredentialType


class Credential(TimestampMixin, Base):
    __tablename__ = "credentials"
    __table_args__ = (UniqueConstraint("server_id", "owner_type", "owner_id"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("cred"))
    server_id: Mapped[str] = mapped_column(ForeignKey("mcp_servers.id"), nullable=False, index=True)
    owner_type: Mapped[IdentityType] = mapped_column(EnumType(IdentityType), nullable=False)
    owner_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    credential_type: Mapped[CredentialType] = mapped_column(
        EnumType(CredentialType), nullable=False
    )
    #: Fernet ciphertext of the JSON secret payload.
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Ciphertext of the refresh token, when the credential is refreshable.
    refresh_ciphertext: Mapped[str | None] = mapped_column(Text)

    @property
    def is_expired(self) -> bool:
        expires = as_aware(self.expires_at)
        return expires is not None and expires <= utcnow()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        # Deliberately omits ciphertext so credentials cannot leak via logs.
        return f"<Credential {self.id} server={self.server_id} owner={self.owner_id}>"
