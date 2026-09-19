"""Authentication: turn a presented credential into a :class:`RequestContext`.

Two credential shapes are accepted:

* a gateway JWT (``Authorization: Bearer <jwt>``) — an access token for a user
  or agent, or a delegated token carrying ``sub`` + ``act.sub``;
* an API key (``Authorization: Bearer aid_sk_...`` or ``X-API-Key``) for a
  machine caller.

This module only answers *who are you?*. Nothing here decides what the caller
may do — that separation is invariant 4.
"""

from __future__ import annotations

from sqlalchemy.orm import Session as DbSession

from ...config import Settings, get_settings
from ...context import RequestContext
from ...errors import AuthenticationError, PersonaViolation
from ...identity.agents import get_agent
from ...identity.api_keys import verify_api_key
from ...identity.delegation import require_active_delegation
from ...identity.sessions import require_active_session
from ...identity.tokens import TokenClaims, TokenService, TokenType
from ...identity.users import get_user
from ...models import AgentKind, IdentityType, Persona


def authenticate(
    db: DbSession,
    *,
    authorization: str | None,
    api_key_header: str | None,
    request_id: str,
    client: str | None = None,
    settings: Settings | None = None,
    tokens: TokenService | None = None,
) -> RequestContext:
    settings = settings or get_settings()
    tokens = tokens or TokenService(settings)

    raw = _extract_credential(authorization, api_key_header, settings)
    if raw is None:
        raise AuthenticationError("missing credential", code="missing_credential")

    if raw.startswith(settings.api_key_prefix):
        return _from_api_key(db, raw, request_id=request_id, client=client, settings=settings)

    claims = tokens.verify(raw)
    return _from_claims(db, claims, request_id=request_id, client=client)


def _extract_credential(
    authorization: str | None, api_key_header: str | None, settings: Settings
) -> str | None:
    if api_key_header:
        return api_key_header.strip()
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    if not value:
        # Tolerate a bare API key without a scheme, but never a bare JWT.
        return authorization.strip() if authorization.startswith(settings.api_key_prefix) else None
    if scheme.lower() != "bearer":
        raise AuthenticationError("expected a Bearer credential", code="unsupported_scheme")
    return value.strip()


def _from_api_key(
    db: DbSession,
    raw: str,
    *,
    request_id: str,
    client: str | None,
    settings: Settings,
) -> RequestContext:
    record = verify_api_key(db, raw, settings=settings)

    if record.owner_type == IdentityType.AGENT:
        agent = get_agent(db, record.owner_id)
        if agent is None or not agent.is_active:
            raise AuthenticationError("agent is unknown or disabled", code="agent_disabled")
        return RequestContext(
            request_id=request_id,
            # An API key authenticates a machine. It can never yield a user
            # persona, however the agent is configured (invariants 2 and 3).
            persona=Persona.NON_USER,
            agent_id=agent.id,
            client=client,
            scopes=("mcp:tools",),
            attributes={"auth": "api_key", "api_key_id": record.id},
        )

    if record.owner_type == IdentityType.SERVICE_ACCOUNT:
        return RequestContext(
            request_id=request_id,
            persona=Persona.NON_USER,
            service_account_id=record.owner_id,
            client=client,
            scopes=("mcp:tools",),
            attributes={"auth": "api_key", "api_key_id": record.id},
        )

    raise AuthenticationError(  # pragma: no cover - issuance forbids this
        "api keys cannot authenticate a human user", code="api_key_persona_violation"
    )


def _from_claims(
    db: DbSession, claims: TokenClaims, *, request_id: str, client: str | None
) -> RequestContext:
    if claims.token_type == TokenType.DOWNSTREAM:
        # Downstream credentials are for MCP servers, not for the gateway.
        raise AuthenticationError(
            "downstream credentials are not accepted here", code="wrong_token_type"
        )

    if claims.session_id:
        require_active_session(db, claims.session_id)

    if claims.is_delegated:
        return _delegated_context(db, claims, request_id=request_id, client=client)

    if claims.subject_type == "user":
        if claims.persona != Persona.USER:
            raise PersonaViolation(
                "user token must carry the user persona", code="persona_mismatch"
            )
        user = get_user(db, claims.sub)
        if user is None or not user.is_active:
            raise AuthenticationError("user is unknown or disabled", code="user_disabled")
        return RequestContext(
            request_id=request_id,
            persona=Persona.USER,
            user_id=user.id,
            session_id=claims.session_id,
            token_id=claims.jti,
            scopes=claims.scopes,
            client=client,
            issued_at=claims.issued_at,
            expires_at=claims.expires_at,
            attributes={"auth": "jwt"},
        )

    if claims.subject_type == "agent":
        if claims.persona == Persona.USER:
            raise PersonaViolation(
                "an agent token cannot claim the user persona", code="persona_mismatch"
            )
        agent = get_agent(db, claims.sub)
        if agent is None or not agent.is_active:
            raise AuthenticationError("agent is unknown or disabled", code="agent_disabled")
        return RequestContext(
            request_id=request_id,
            persona=Persona.NON_USER,
            agent_id=agent.id,
            session_id=claims.session_id,
            token_id=claims.jti,
            scopes=claims.scopes,
            client=client,
            issued_at=claims.issued_at,
            expires_at=claims.expires_at,
            attributes={"auth": "jwt"},
        )

    if claims.subject_type == "service_account":
        if claims.persona == Persona.USER:
            raise PersonaViolation(
                "a service account cannot claim the user persona", code="persona_mismatch"
            )
        return RequestContext(
            request_id=request_id,
            persona=Persona.NON_USER,
            service_account_id=claims.sub,
            session_id=claims.session_id,
            token_id=claims.jti,
            scopes=claims.scopes,
            client=client,
            issued_at=claims.issued_at,
            expires_at=claims.expires_at,
            attributes={"auth": "jwt"},
        )

    raise AuthenticationError(
        f"unsupported subject type: {claims.subject_type}", code="unsupported_subject"
    )


def _delegated_context(
    db: DbSession, claims: TokenClaims, *, request_id: str, client: str | None
) -> RequestContext:
    if claims.persona != Persona.USER:
        raise PersonaViolation(
            "a delegated token must carry the user persona", code="persona_mismatch"
        )
    user = get_user(db, claims.sub)
    if user is None or not user.is_active:
        raise AuthenticationError("user is unknown or disabled", code="user_disabled")

    agent = get_agent(db, claims.act_sub or "")
    if agent is None or not agent.is_active:
        raise AuthenticationError("agent is unknown or disabled", code="agent_disabled")
    if agent.kind == AgentKind.AUTONOMOUS:
        raise PersonaViolation(
            f"autonomous agent {agent.name} cannot act for a user",
            code="autonomous_agent_delegation",
        )

    if claims.delegation_id:
        # A revoked or expired delegation invalidates the token immediately,
        # without waiting for its own expiry.
        require_active_delegation(db, claims.delegation_id)

    return RequestContext(
        request_id=request_id,
        persona=Persona.USER,
        user_id=user.id,
        agent_id=agent.id,
        session_id=claims.session_id,
        delegation_id=claims.delegation_id,
        token_id=claims.jti,
        scopes=claims.scopes,
        client=client,
        issued_at=claims.issued_at,
        expires_at=claims.expires_at,
        attributes={"auth": "delegated"},
    )
