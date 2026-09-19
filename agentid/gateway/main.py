"""The AgentID gateway application.

    Client -> authenticate -> resolve identity -> authorize -> resolve
    credential -> route -> audit -> response

The gateway holds no business logic belonging to downstream systems; it owns
identity, authorization, credentials, discovery, routing and the audit trail.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .. import __version__
from ..audit.logger import AuditLogger
from ..authorization.engine import AuthorizationEngine
from ..config import Settings, get_settings
from ..credentials.manager import CredentialManager
from ..database.engine import create_all, get_engine
from ..errors import AgentIDError
from ..identity.tokens import TokenService
from .api import ROUTERS
from .mcp.proxy import McpProxy
from .middleware.context import RequestIdMiddleware
from .middleware.ratelimit import RateLimiter
from .services.mcp_service import McpService

logger = logging.getLogger("agentid.gateway")

DESCRIPTION = """
Zero-trust identity and security gateway for MCP agents.

Authenticate the actor, authorize the action, protect the credential, and
record the decision.
"""


def create_app(
    *,
    settings: Settings | None = None,
    http_client: httpx.AsyncClient | None = None,
    audit: AuditLogger | None = None,
    create_schema: bool = True,
) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if create_schema:
            create_all(get_engine())
        logger.info("AgentID gateway %s starting (env=%s)", __version__, settings.environment)
        yield
        await app.state.proxy.aclose()

    app = FastAPI(
        title="AgentID Gateway",
        description=DESCRIPTION,
        version=__version__,
        lifespan=lifespan,
    )

    app.state.settings = settings
    app.state.tokens = TokenService(settings)
    app.state.authorization = AuthorizationEngine(settings)
    app.state.credentials = CredentialManager(settings=settings, tokens=app.state.tokens)
    app.state.proxy = McpProxy(settings=settings, client=http_client)
    app.state.audit = audit or AuditLogger(settings=settings)
    app.state.rate_limiter = RateLimiter(settings=settings)
    app.state.mcp_service = McpService(
        engine=app.state.authorization,
        credentials=app.state.credentials,
        proxy=app.state.proxy,
        audit=app.state.audit,
        settings=settings,
    )

    app.add_middleware(RequestIdMiddleware)

    for router in ROUTERS:
        app.include_router(router)

    _install_error_handlers(app)
    _install_meta_routes(app, settings)
    return app


def _install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AgentIDError)
    async def agentid_error_handler(request: Request, exc: AgentIDError) -> JSONResponse:
        payload: dict[str, Any] = exc.to_dict()
        payload["request_id"] = request.scope.get("state", {}).get("request_id")
        headers = {}
        if exc.status_code == 401:
            headers["WWW-Authenticate"] = "Bearer"
        if exc.status_code == 429:
            headers["Retry-After"] = str(exc.details.get("retry_after", 1))
        return JSONResponse(status_code=exc.status_code, content=payload, headers=headers)


def _install_meta_routes(app: FastAPI, settings: Settings) -> None:
    @app.get("/health", tags=["meta"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__, "environment": settings.environment}

    @app.get("/", tags=["meta"])
    async def root() -> dict[str, Any]:
        return {
            "name": "AgentID Gateway",
            "version": __version__,
            "description": "Identity and security infrastructure between AI agents and MCP servers",
            "endpoints": {
                "authentication": "/auth/login, /auth/token (RFC 8693), /auth/whoami",
                "discovery": "/mcp/tools, /mcp/tools/search",
                "invocation": "/mcp/call",
                "registry": "/registry/servers",
                "audit": "/audit/events",
                "docs": "/docs",
            },
        }


app = create_app()
