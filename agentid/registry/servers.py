"""MCP server registry."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..errors import ConflictError, NotFoundError
from ..models import CredentialType, McpServer


def register_server(
    db: DbSession,
    *,
    name: str,
    endpoint: str,
    credential_type: CredentialType = CredentialType.NONE,
    description: str | None = None,
    audience: str | None = None,
    enabled: bool = True,
    capabilities: dict[str, Any] | None = None,
) -> McpServer:
    if get_server_by_name(db, name) is not None:
        raise ConflictError(f"server already registered: {name}", code="server_exists")
    server = McpServer(
        name=name,
        endpoint=endpoint.rstrip("/"),
        credential_type=credential_type,
        description=description,
        audience=audience,
        enabled=enabled,
        capabilities=capabilities or {},
    )
    db.add(server)
    db.flush()
    return server


def get_server(db: DbSession, server_id: str) -> McpServer | None:
    return db.get(McpServer, server_id)


def get_server_by_name(db: DbSession, name: str) -> McpServer | None:
    return db.scalar(select(McpServer).where(McpServer.name == name))


def resolve_server(db: DbSession, identifier: str) -> McpServer | None:
    return get_server_by_name(db, identifier) or get_server(db, identifier)


def require_server(db: DbSession, identifier: str) -> McpServer:
    server = resolve_server(db, identifier)
    if server is None:
        raise NotFoundError(f"unknown MCP server: {identifier}", code="unknown_server")
    return server


def list_servers(db: DbSession, *, enabled_only: bool = False) -> list[McpServer]:
    stmt = select(McpServer).order_by(McpServer.name)
    if enabled_only:
        stmt = stmt.where(McpServer.enabled.is_(True))
    return list(db.scalars(stmt))


def set_enabled(db: DbSession, identifier: str, enabled: bool) -> McpServer:
    server = require_server(db, identifier)
    server.enabled = enabled
    db.flush()
    return server


def update_server(
    db: DbSession,
    identifier: str,
    *,
    endpoint: str | None = None,
    description: str | None = None,
    audience: str | None = None,
    credential_type: CredentialType | None = None,
    capabilities: dict[str, Any] | None = None,
) -> McpServer:
    server = require_server(db, identifier)
    if endpoint is not None:
        server.endpoint = endpoint.rstrip("/")
    if description is not None:
        server.description = description
    if audience is not None:
        server.audience = audience
    if credential_type is not None:
        server.credential_type = credential_type
    if capabilities is not None:
        server.capabilities = capabilities
    db.flush()
    return server


def delete_server(db: DbSession, identifier: str) -> None:
    server = require_server(db, identifier)
    db.delete(server)
    db.flush()
