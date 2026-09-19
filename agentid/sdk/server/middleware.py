"""FastAPI/Starlette glue for downstream MCP servers.

Usage in a server::

    from agentid.sdk.server import TokenVerifier, gateway_identity, install

    app = FastAPI()
    install(app, TokenVerifier(secret=..., audience="agentid-mcp:github"))

    @app.post("/tools/create_issue")
    def create_issue(body: dict, identity: GatewayClaims = Depends(gateway_identity)):
        authorize_resource(identity, body["repo"])   # the server's own rules
        ...
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .claims import GatewayClaims
from .verifier import TokenVerifier, VerificationError

#: Paths that never require a gateway credential.
DEFAULT_PUBLIC_PATHS = ("/health", "/healthz", "/openapi.json", "/docs", "/redoc")

_VERIFIER_ATTR = "agentid_verifier"


class GatewayAuthMiddleware:
    """Pure-ASGI middleware verifying the gateway credential on every request."""

    def __init__(
        self,
        app: Any,
        *,
        verifier: TokenVerifier,
        public_paths: tuple[str, ...] = DEFAULT_PUBLIC_PATHS,
    ) -> None:
        self.app = app
        self.verifier = verifier
        self.public_paths = public_paths

    async def __call__(self, scope: dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":  # pragma: no cover - websockets unsupported
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path in self.public_paths:
            await self.app(scope, receive, send)
            return

        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }
        try:
            claims = self.verifier.verify_header(headers.get("authorization"))
        except VerificationError as exc:
            response = JSONResponse(
                status_code=401, content={"error": exc.code, "message": str(exc)}
            )
            await response(scope, receive, send)
            return

        scope.setdefault("state", {})["agentid_identity"] = claims
        await self.app(scope, receive, send)


def install(
    app: FastAPI,
    verifier: TokenVerifier,
    *,
    public_paths: tuple[str, ...] = DEFAULT_PUBLIC_PATHS,
) -> FastAPI:
    setattr(app.state, _VERIFIER_ATTR, verifier)
    app.add_middleware(GatewayAuthMiddleware, verifier=verifier, public_paths=public_paths)
    return app


def gateway_identity(request: Request) -> GatewayClaims:
    """FastAPI dependency returning the verified gateway claims."""
    claims = getattr(request.state, "agentid_identity", None)
    if claims is None:  # pragma: no cover - middleware guarantees this
        raise VerificationError("request was not authenticated by the gateway middleware")
    return claims


async def verification_error_handler(
    _request: Request, exc: Exception
) -> JSONResponse:  # pragma: no cover - wiring
    error = exc if isinstance(exc, VerificationError) else VerificationError(str(exc))
    return JSONResponse(status_code=401, content={"error": error.code, "message": str(error)})


def require_scope(claims: GatewayClaims, scope: str) -> None:
    if claims.scopes and scope not in claims.scopes:
        raise VerificationError(f"credential is missing scope {scope}", code="missing_scope")


AsyncHandler = Callable[[Request], Awaitable[Any]]
