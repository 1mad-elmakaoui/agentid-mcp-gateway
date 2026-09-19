"""MCP server registry and tool catalog."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Boolean, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, EnumType, TimestampMixin, new_id


class CredentialType(StrEnum):
    #: No downstream credential beyond the gateway-issued token.
    NONE = "none"
    OAUTH = "oauth"
    API_KEY = "api_key"
    SERVICE_ACCOUNT = "service_account"


class McpServer(TimestampMixin, Base):
    __tablename__ = "mcp_servers"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("srv"))
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    endpoint: Mapped[str] = mapped_column(String(500), nullable=False)
    credential_type: Mapped[CredentialType] = mapped_column(
        EnumType(CredentialType), default=CredentialType.NONE, nullable=False
    )
    #: Audience placed in the gateway-issued token for this server.
    audience: Mapped[str | None] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    #: Free-form capability metadata reported by the server.
    capabilities: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    tools: Mapped[list[Tool]] = relationship(
        back_populates="server", lazy="selectin", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<McpServer {self.name}>"


class Tool(TimestampMixin, Base):
    __tablename__ = "tools"
    __table_args__ = (UniqueConstraint("server_id", "name"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("tool"))
    server_id: Mapped[str] = mapped_column(ForeignKey("mcp_servers.id"), nullable=False, index=True)
    #: Bare tool name as the downstream server knows it, e.g. ``create_issue``.
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    #: Fully qualified name used in policies, e.g. ``github.create_issue``.
    qualified_name: Mapped[str] = mapped_column(
        String(400), unique=True, nullable=False, index=True
    )
    description: Mapped[str | None] = mapped_column(Text)
    input_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    #: Permission required to invoke the tool. Defaults to the qualified name.
    required_permission: Mapped[str | None] = mapped_column(String(400))
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    #: Tools that must run under a service account rather than the caller.
    requires_service_account: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    default_service_account_id: Mapped[str | None] = mapped_column(
        ForeignKey("service_accounts.id")
    )

    server: Mapped[McpServer] = relationship(back_populates="tools", lazy="joined")

    @property
    def permission(self) -> str:
        return self.required_permission or self.qualified_name

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Tool {self.qualified_name}>"
