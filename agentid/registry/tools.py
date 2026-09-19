"""Tool catalog and permission-aware discovery.

An agent must not be handed the schemas of hundreds of tools it may not call
(architecture §14). Discovery therefore filters on *query + identity +
permissions + available servers* and returns only what the caller could
actually invoke.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..context import RequestContext
from ..errors import ConflictError, NotFoundError
from ..models import McpServer, Tool
from .servers import require_server


def register_tool(
    db: DbSession,
    *,
    server: McpServer | str,
    name: str,
    description: str | None = None,
    input_schema: dict[str, Any] | None = None,
    required_permission: str | None = None,
    tags: list[str] | None = None,
    requires_service_account: bool = False,
    default_service_account_id: str | None = None,
    enabled: bool = True,
) -> Tool:
    srv = server if isinstance(server, McpServer) else require_server(db, server)
    qualified = f"{srv.name}.{name}"
    if get_tool(db, qualified) is not None:
        raise ConflictError(f"tool already registered: {qualified}", code="tool_exists")
    tool = Tool(
        server_id=srv.id,
        name=name,
        qualified_name=qualified,
        description=description,
        input_schema=input_schema or {},
        required_permission=required_permission or qualified,
        tags=tags or [],
        requires_service_account=requires_service_account,
        default_service_account_id=default_service_account_id,
        enabled=enabled,
    )
    db.add(tool)
    db.flush()
    return tool


def get_tool(db: DbSession, qualified_name: str) -> Tool | None:
    return db.scalar(select(Tool).where(Tool.qualified_name == qualified_name))


def require_tool(db: DbSession, qualified_name: str) -> Tool:
    tool = get_tool(db, qualified_name)
    if tool is None:
        raise NotFoundError(f"unknown tool: {qualified_name}", code="unknown_tool")
    return tool


def list_tools(
    db: DbSession, *, server: str | None = None, enabled_only: bool = True
) -> list[Tool]:
    stmt = select(Tool).order_by(Tool.qualified_name)
    if enabled_only:
        stmt = stmt.where(Tool.enabled.is_(True))
    if server:
        srv = require_server(db, server)
        stmt = stmt.where(Tool.server_id == srv.id)
    return list(db.scalars(stmt))


def delete_tool(db: DbSession, qualified_name: str) -> None:
    tool = require_tool(db, qualified_name)
    db.delete(tool)
    db.flush()


# -- search --------------------------------------------------------------


@dataclass(slots=True)
class ToolMatch:
    tool: Tool
    score: float
    #: Why the caller may invoke it, for explainable discovery.
    permission: str

    def to_dict(self, *, include_schema: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.tool.qualified_name,
            "server": self.tool.server.name,
            "tool": self.tool.name,
            "description": self.tool.description,
            "tags": self.tool.tags,
            "required_permission": self.permission,
            "requires_service_account": self.tool.requires_service_account,
            "score": round(self.score, 4),
        }
        if include_schema:
            payload["input_schema"] = self.tool.input_schema
        return payload


def _tokens(text: str) -> list[str]:
    cleaned = "".join(ch.lower() if ch.isalnum() else " " for ch in text)
    return [t for t in cleaned.split() if t]


def score_tool(tool: Tool, query: str) -> float:
    """A small lexical score: exact name beats prefix beats token overlap."""
    if not query.strip():
        return 0.5
    q = query.strip().lower()
    qualified = tool.qualified_name.lower()
    if q == qualified or q == tool.name.lower():
        return 1.0
    score = 0.0
    if qualified.startswith(q) or tool.name.lower().startswith(q):
        score = max(score, 0.9)
    if q in qualified:
        score = max(score, 0.8)

    q_tokens = set(_tokens(q))
    if not q_tokens:
        return score
    haystack = " ".join(
        filter(None, [tool.qualified_name, tool.description or "", " ".join(tool.tags or [])])
    )
    h_tokens = set(_tokens(haystack))
    overlap = q_tokens & h_tokens
    if overlap:
        score = max(score, 0.4 + 0.5 * (len(overlap) / len(q_tokens)))
    return score


def search_tools(
    db: DbSession,
    *,
    query: str = "",
    ctx: RequestContext | None = None,
    permitted: Iterable[str] | None = None,
    servers: Iterable[str] | None = None,
    limit: int = 20,
    min_score: float = 0.35,
) -> list[ToolMatch]:
    """Rank enabled tools by relevance, restricted to ``permitted`` names.

    ``permitted`` is the set of fully-qualified tool names the caller is
    authorized to invoke; callers that pass ``None`` get the unfiltered
    catalog, which is only appropriate for administrative use.
    """
    stmt = select(Tool).where(Tool.enabled.is_(True))
    rows = list(db.scalars(stmt))

    allowed_servers = set(servers) if servers else None
    permitted_set = set(permitted) if permitted is not None else None

    matches: list[ToolMatch] = []
    for tool in rows:
        if not tool.server.enabled:
            continue
        if allowed_servers is not None and tool.server.name not in allowed_servers:
            continue
        if permitted_set is not None and tool.qualified_name not in permitted_set:
            continue
        score = score_tool(tool, query)
        if query.strip() and score < min_score:
            continue
        matches.append(ToolMatch(tool=tool, score=score, permission=tool.permission))

    matches.sort(key=lambda m: (-m.score, m.tool.qualified_name))
    return matches[:limit]
