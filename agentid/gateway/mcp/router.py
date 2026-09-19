"""Routing: which MCP server owns a tool, and where does it live."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session as DbSession

from ...errors import NotFoundError
from ...models import McpServer, Tool
from ...registry.tools import get_tool


@dataclass(slots=True)
class Route:
    tool: Tool
    server: McpServer

    @property
    def url(self) -> str:
        return f"{self.server.endpoint}/mcp"

    @property
    def qualified_name(self) -> str:
        return self.tool.qualified_name

    @property
    def downstream_name(self) -> str:
        """The bare name the downstream server knows the tool by."""
        return self.tool.name


def resolve_route(db: DbSession, tool_name: str, *, server_hint: str | None = None) -> Route:
    """Resolve ``github.create_issue`` (or ``create_issue`` plus a server hint).

    Routing deliberately does *not* consider identity: authorization happens
    before the router's output is used (invariant 5).
    """
    qualified = tool_name
    if "." not in tool_name:
        if not server_hint:
            raise NotFoundError(
                f"tool name must be qualified as <server>.<tool>: {tool_name}",
                code="unqualified_tool",
            )
        qualified = f"{server_hint}.{tool_name}"

    tool = get_tool(db, qualified)
    if tool is None:
        raise NotFoundError(f"unknown tool: {qualified}", code="unknown_tool")
    if server_hint and tool.server.name != server_hint:
        raise NotFoundError(
            f"tool {qualified} does not belong to server {server_hint}", code="unknown_tool"
        )
    return Route(tool=tool, server=tool.server)
