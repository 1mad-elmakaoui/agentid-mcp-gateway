"""The MCP surface agents actually talk to: discovery and invocation."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ...registry.servers import list_servers
from ..deps import ContextDep, DbDep, get_mcp_service
from ..services.mcp_service import McpService
from .schemas import CallToolRequest, CallToolResponse, ToolSearchRequest

router = APIRouter(prefix="/mcp", tags=["mcp"])

ServiceDep = Annotated[McpService, Depends(get_mcp_service)]


@router.get("/servers")
def servers(ctx: ContextDep, db: DbDep, service: ServiceDep) -> dict[str, object]:
    """Servers that expose at least one tool this caller may invoke."""
    result = service.discover_tools(db, ctx, query="", limit=500)
    db.commit()
    reachable = {m.tool.server.name for m in result.matches}
    return {
        "servers": [
            {
                "name": s.name,
                "description": s.description,
                "enabled": s.enabled,
                "tool_count": sum(1 for m in result.matches if m.tool.server.name == s.name),
            }
            for s in list_servers(db, enabled_only=True)
            if s.name in reachable
        ]
    }


@router.get("/tools")
def list_permitted_tools(
    ctx: ContextDep,
    db: DbDep,
    service: ServiceDep,
    query: Annotated[str, Query()] = "",
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
    include_schema: bool = True,
) -> dict[str, object]:
    result = service.discover_tools(db, ctx, query=query, limit=limit)
    db.commit()
    return result.to_dict(include_schema=include_schema)


@router.post("/tools/search")
def search_tools(
    body: ToolSearchRequest, ctx: ContextDep, db: DbDep, service: ServiceDep
) -> dict[str, object]:
    """Intent-driven discovery: "I need to create a GitHub issue".

    Only tools the caller is authorized to invoke are returned, so an agent
    never even learns the schema of a tool it could not call.
    """
    result = service.discover_tools(
        db, ctx, query=body.query, servers=body.servers, limit=body.limit
    )
    db.commit()
    return result.to_dict(include_schema=body.include_schema)


@router.post("/call", response_model=CallToolResponse)
async def call_tool(
    body: CallToolRequest, ctx: ContextDep, db: DbDep, service: ServiceDep
) -> CallToolResponse:
    """Authenticate -> authorize -> resolve credential -> route -> audit."""
    try:
        outcome = await service.call_tool(
            db,
            ctx,
            tool_name=body.tool,
            arguments=body.arguments,
            server_hint=body.server,
            service_account=body.service_account,
            resource=body.resource,
        )
    finally:
        # Audit events are written on every path, including denials.
        db.commit()

    assert outcome.route is not None and outcome.response is not None
    return CallToolResponse(
        request_id=ctx.request_id,
        tool=outcome.route.qualified_name,
        server=outcome.route.server.name,
        decision=outcome.decision.effect.value,
        execution_identity=ctx.execution_identity,
        result=outcome.response.result,
        error=outcome.response.error,
        latency_ms=outcome.latency_ms,
    )
