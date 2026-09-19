"""Shared scaffolding for the example MCP servers.

A downstream server stays deliberately simple (architecture §18):

    verify gateway credential -> resource authorization -> execute tool

It performs no identity resolution of its own and holds no user database.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..sdk.server import GatewayClaims, TokenVerifier, install

ToolHandler = Callable[[GatewayClaims, dict[str, Any]], dict[str, Any]]


class ResourceDenied(Exception):
    """The gateway allowed the tool; this server denies the resource.

    Gateway authorization answers "may this identity use this tool"; the server
    still answers "may this identity touch *this* resource" (invariant 10).
    """

    def __init__(self, message: str, *, resource: str | None = None) -> None:
        super().__init__(message)
        self.resource = resource


@dataclass(slots=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolHandler


def text(content: str, *, is_error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": content}], "isError": is_error}


def build_server(
    *,
    title: str,
    audience: str,
    tools: list[ToolSpec],
    secret: str | None = None,
    issuer: str | None = None,
) -> FastAPI:
    """Create an MCP server that trusts only gateway-issued credentials."""
    app = FastAPI(title=title)
    verifier = TokenVerifier(
        secret=secret or os.environ.get("AGENTID_SECRET_KEY", "dev-only-insecure-secret-change-me"),
        audience=audience,
        issuer=issuer or os.environ.get("AGENTID_JWT_ISSUER", "agentid"),
    )
    install(app, verifier)
    registry = {spec.name: spec for spec in tools}
    app.state.tools = registry
    app.state.audience = audience

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "server": title, "audience": audience}

    @app.post("/mcp")
    async def mcp_endpoint(request: Request) -> JSONResponse:
        body = await request.json()
        request_id = body.get("id")
        method = body.get("method")
        claims: GatewayClaims = request.scope["state"]["agentid_identity"]

        if method == "tools/list":
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "tools": [
                            {
                                "name": spec.name,
                                "description": spec.description,
                                "inputSchema": spec.input_schema,
                            }
                            for spec in registry.values()
                        ]
                    },
                }
            )

        if method != "tools/call":
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                },
                status_code=400,
            )

        params = body.get("params") or {}
        name = params.get("name")
        spec = registry.get(name)
        if spec is None:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32602, "message": f"unknown tool: {name}"},
                },
                status_code=404,
            )

        try:
            result = spec.handler(claims, params.get("arguments") or {})
        except ResourceDenied as exc:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32003,
                        "message": str(exc),
                        "data": {"reason": "resource_forbidden", "resource": exc.resource},
                    },
                },
                status_code=403,
            )
        except Exception as exc:  # pragma: no cover - defensive
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32603, "message": str(exc)},
                },
                status_code=500,
            )

        return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": result})

    return app
