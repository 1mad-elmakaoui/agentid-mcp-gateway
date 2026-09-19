"""FastAPI dependencies.

Single place where the gateway's collaborators are constructed, so tests can
override any one of them.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session as DbSession

from ..audit.logger import AuditLogger, get_audit_logger
from ..authorization.engine import AuthorizationEngine
from ..authorization.rbac import (
    permissions_for_agent,
    permissions_for_service_account,
    permissions_for_user,
)
from ..config import Settings, get_settings
from ..context import RequestContext
from ..credentials.manager import CredentialManager
from ..database.engine import db_session
from ..errors import AuthorizationError
from ..identity.agents import get_agent
from ..identity.service_accounts import get_service_account
from ..identity.tokens import TokenService
from ..identity.users import get_user
from ..models import Persona
from .mcp.proxy import McpProxy
from .middleware.auth import authenticate
from .middleware.ratelimit import RateLimiter
from .services.mcp_service import McpService

ADMIN_PERMISSION = "agentid.admin"


def get_db() -> Iterator[DbSession]:
    yield from db_session()


def get_config() -> Settings:
    return get_settings()


def get_token_service(request: Request) -> TokenService:
    return request.app.state.tokens


def get_auth_engine(request: Request) -> AuthorizationEngine:
    return request.app.state.authorization


def get_credential_manager(request: Request) -> CredentialManager:
    return request.app.state.credentials


def get_proxy(request: Request) -> McpProxy:
    return request.app.state.proxy


def get_audit(request: Request) -> AuditLogger:
    return getattr(request.app.state, "audit", None) or get_audit_logger()


def get_mcp_service(request: Request) -> McpService:
    return request.app.state.mcp_service


def get_rate_limiter(request: Request) -> RateLimiter:
    return request.app.state.rate_limiter


def get_request_id(request: Request) -> str:
    return request.scope.get("state", {}).get("request_id") or "req_unknown"


DbDep = Annotated[DbSession, Depends(get_db)]


def current_context(
    request: Request,
    db: DbDep,
    authorization: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header()] = None,
) -> RequestContext:
    """Authenticate the caller and build the request context.

    Every non-public route depends on this, which is how invariant 1 — every
    request has an authenticated identity — is enforced structurally.
    """
    settings: Settings = request.app.state.settings
    request_id = get_request_id(request)
    ctx = authenticate(
        db,
        authorization=authorization,
        api_key_header=x_api_key,
        request_id=request_id,
        client=request.client.host if request.client else None,
        settings=settings,
        tokens=request.app.state.tokens,
    )
    limiter: RateLimiter = request.app.state.rate_limiter
    limiter.check(_rate_limit_key(ctx))
    request.scope.setdefault("state", {})["agentid_context"] = ctx
    return ctx


def _rate_limit_key(ctx: RequestContext) -> str:
    if ctx.execution_identity != "anonymous":
        return ctx.execution_identity
    return ctx.client or "anon"


ContextDep = Annotated[RequestContext, Depends(current_context)]


def require_admin(ctx: ContextDep, db: DbDep) -> RequestContext:
    """Administrative routes require the ``agentid.admin`` permission."""
    permissions = _permissions_for(db, ctx)
    if permissions is None or not permissions.permits(ADMIN_PERMISSION):
        raise AuthorizationError(
            "administrative access requires the agentid.admin permission",
            code="missing_permission",
        )
    return ctx


AdminDep = Annotated[RequestContext, Depends(require_admin)]


def _permissions_for(db: DbSession, ctx: RequestContext):
    if ctx.user_id:
        user = get_user(db, ctx.user_id)
        if user is None:
            return None
        base = permissions_for_user(db, user)
        if ctx.agent_id:
            agent = get_agent(db, ctx.agent_id)
            # A delegated caller is still bounded by the agent's own grants.
            if agent is None:
                return None
            agent_permissions = permissions_for_agent(db, agent)
            return base.intersect(agent_permissions) if agent_permissions else base
        return base
    if ctx.agent_id:
        agent = get_agent(db, ctx.agent_id)
        return permissions_for_agent(db, agent) if agent else None
    if ctx.service_account_id:
        sa = get_service_account(db, ctx.service_account_id)
        return permissions_for_service_account(db, sa) if sa else None
    return None


def user_persona_only(ctx: ContextDep) -> RequestContext:
    """Guard for routes that only make sense for a human caller."""
    if ctx.persona != Persona.USER or ctx.user_id is None:
        raise AuthorizationError(
            "this endpoint requires a human user identity", code="persona_violation"
        )
    return ctx


UserDep = Annotated[RequestContext, Depends(user_persona_only)]
