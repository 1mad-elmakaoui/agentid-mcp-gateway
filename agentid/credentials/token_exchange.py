"""RFC 8693 style token exchange.

Two exchanges are supported:

``urn:ietf:params:oauth:token-type:access_token`` (delegation)
    A user token plus an ``actor_token``/agent identifier is exchanged for a
    delegated token carrying ``sub`` (user) and ``act.sub`` (agent).

``downstream``
    Internal exchange performed by the proxy: the request context is turned
    into a short-lived, single-audience credential for one MCP server.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session as DbSession

from ..config import Settings, get_settings
from ..context import RequestContext
from ..errors import ValidationError
from ..identity.delegation import delegate
from ..identity.tokens import TokenService
from ..identity.users import require_user
from ..models import Persona

TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"
GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"

SUPPORTED_TOKEN_TYPES = {TOKEN_TYPE_ACCESS, TOKEN_TYPE_JWT}


@dataclass(slots=True)
class ExchangeResult:
    access_token: str
    issued_token_type: str
    token_type: str
    expires_in: int
    scope: str | None
    delegation_id: str | None = None


def exchange_for_delegation(
    db: DbSession,
    *,
    user_id: str,
    agent_identifier: str,
    grant_type: str = GRANT_TYPE_TOKEN_EXCHANGE,
    requested_token_type: str = TOKEN_TYPE_JWT,
    session_id: str | None = None,
    scopes: tuple[str, ...] | list[str] = ("mcp:tools",),
    settings: Settings | None = None,
    tokens: TokenService | None = None,
) -> ExchangeResult:
    settings = settings or get_settings()
    if grant_type != GRANT_TYPE_TOKEN_EXCHANGE:
        raise ValidationError(
            f"unsupported grant_type: {grant_type}", code="unsupported_grant_type"
        )
    if requested_token_type not in SUPPORTED_TOKEN_TYPES:
        raise ValidationError(
            f"unsupported requested_token_type: {requested_token_type}",
            code="unsupported_token_type",
        )

    user = require_user(db, user_id)
    result = delegate(
        db,
        user=user,
        agent_identifier=agent_identifier,
        session_id=session_id,
        scopes=scopes,
        settings=settings,
        tokens=tokens,
    )
    return ExchangeResult(
        access_token=result.token,
        issued_token_type=TOKEN_TYPE_JWT,
        token_type="Bearer",
        expires_in=settings.delegated_token_ttl_seconds,
        scope=" ".join(scopes) if scopes else None,
        delegation_id=result.delegation.id,
    )


def exchange_for_downstream(
    ctx: RequestContext,
    *,
    server_name: str,
    audience: str | None = None,
    tool: str | None = None,
    settings: Settings | None = None,
    tokens: TokenService | None = None,
) -> str:
    """Mint the credential the downstream MCP server will verify."""
    settings = settings or get_settings()
    tokens = tokens or TokenService(settings)
    return tokens.issue_downstream_token(
        server_name=server_name,
        audience=audience,
        user_id=ctx.user_id,
        agent_id=ctx.agent_id,
        service_account_id=ctx.service_account_id,
        persona=ctx.persona or Persona.USER,
        tool=tool or ctx.tool,
        request_id=ctx.request_id,
        scopes=ctx.scopes,
    )
