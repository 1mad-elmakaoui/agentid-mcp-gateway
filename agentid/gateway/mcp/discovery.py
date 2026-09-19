"""Permission-aware tool discovery.

The agent asks "I need to create a GitHub issue" and gets back only the tools
it is actually allowed to invoke. Filtering before ranking — rather than after —
means an agent never learns that a tool it cannot use exists.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from sqlalchemy.orm import Session as DbSession

from ...authorization.decisions import Decision
from ...authorization.engine import AuthorizationEngine
from ...context import RequestContext
from ...registry.tools import ToolMatch, list_tools, search_tools


@dataclass(slots=True)
class DiscoveryResult:
    matches: list[ToolMatch]
    #: Tools that exist but the caller may not invoke. Counted, never named.
    filtered_out: int
    query: str

    def to_dict(self, *, include_schema: bool = True) -> dict[str, Any]:
        return {
            "query": self.query,
            "count": len(self.matches),
            "filtered_out": self.filtered_out,
            "tools": [m.to_dict(include_schema=include_schema) for m in self.matches],
        }


def permitted_tool_names(
    db: DbSession, ctx: RequestContext, engine: AuthorizationEngine
) -> tuple[set[str], dict[str, Decision]]:
    """Evaluate the full catalog against the caller's effective permissions."""
    permitted: set[str] = set()
    decisions: dict[str, Decision] = {}
    for tool in list_tools(db):
        probe = replace(ctx, server=tool.server.name, tool=tool.qualified_name)
        decision = engine.authorize_tool(db, probe, tool)
        decisions[tool.qualified_name] = decision
        if decision.allowed:
            permitted.add(tool.qualified_name)
    return permitted, decisions


def discover(
    db: DbSession,
    ctx: RequestContext,
    *,
    engine: AuthorizationEngine,
    query: str = "",
    servers: list[str] | None = None,
    limit: int = 20,
) -> DiscoveryResult:
    permitted, decisions = permitted_tool_names(db, ctx, engine)
    matches = search_tools(
        db, query=query, ctx=ctx, permitted=permitted, servers=servers, limit=limit
    )
    return DiscoveryResult(
        matches=matches,
        filtered_out=len(decisions) - len(permitted),
        query=query,
    )
