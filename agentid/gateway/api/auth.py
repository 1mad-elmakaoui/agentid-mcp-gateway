"""Authentication endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from ...audit.events import Action, Outcome
from ...config import Settings
from ...context import RequestContext
from ...credentials.token_exchange import exchange_for_delegation
from ...errors import AuthenticationError, PersonaViolation
from ...identity.sessions import create_session, revoke_session
from ...identity.tokens import TokenService, TokenType
from ...identity.users import authenticate_user
from ...models import IdentityType, Persona
from ..deps import ContextDep, DbDep, get_audit, get_config, get_request_id, get_token_service
from .schemas import (
    IntrospectRequest,
    LoginRequest,
    TokenExchangeRequest,
    TokenResponse,
    WhoAmIResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest,
    request: Request,
    db: DbDep,
    settings: Annotated[Settings, Depends(get_config)],
    tokens: Annotated[TokenService, Depends(get_token_service)],
) -> TokenResponse:
    """Password login for a human user. Returns a user-persona access token."""
    audit = get_audit(request)
    request_id = get_request_id(request)
    try:
        user = authenticate_user(db, email=body.email, password=body.password)
    except AuthenticationError as exc:
        audit.record(
            db,
            _failure_record(
                request_id=request_id, action=Action.AUTH_TOKEN, reason=exc.code, subject=body.email
            ),
        )
        db.commit()
        raise

    session = create_session(
        db,
        subject_type=IdentityType.USER,
        subject_id=user.id,
        persona=Persona.USER,
        client=request.client.host if request.client else None,
        settings=settings,
    )
    token, claims = tokens.issue_access_token(
        subject=user.id,
        persona=Persona.USER,
        subject_type="user",
        session_id=session.id,
    )
    ctx = RequestContext(
        request_id=request_id, persona=Persona.USER, user_id=user.id, session_id=session.id
    )
    audit.log(db, ctx, action=Action.AUTH_TOKEN, decision=Outcome.ALLOW, reason="password")
    db.commit()
    return TokenResponse(
        access_token=token,
        expires_in=settings.access_token_ttl_seconds,
        scope=" ".join(claims.scopes),
        session_id=session.id,
    )


@router.post("/token", response_model=TokenResponse)
def token_exchange(
    body: TokenExchangeRequest,
    request: Request,
    db: DbDep,
    settings: Annotated[Settings, Depends(get_config)],
    tokens: Annotated[TokenService, Depends(get_token_service)],
) -> TokenResponse:
    """RFC 8693 exchange: a user token + an agent -> a delegated token.

    The issued token carries ``sub`` (the user) and ``act.sub`` (the agent), so
    both identities survive into authorization and the audit trail.
    """
    audit = get_audit(request)
    request_id = get_request_id(request)

    claims = tokens.verify(body.subject_token)
    if claims.token_type == TokenType.DOWNSTREAM:
        raise AuthenticationError(
            "downstream credentials cannot be exchanged", code="wrong_token_type"
        )
    if claims.subject_type != "user" or claims.persona != Persona.USER:
        # Only a human may delegate. A machine identity exchanging its token for
        # a user-persona token is exactly the escalation invariant 3 forbids.
        raise PersonaViolation(
            "only a user token can be exchanged for a delegated token",
            code="persona_violation",
        )
    if claims.session_id:
        from ...identity.sessions import require_active_session

        require_active_session(db, claims.session_id)

    scopes = tuple(body.scope.split()) if body.scope else ("mcp:tools",)
    ctx = RequestContext(
        request_id=request_id,
        persona=Persona.USER,
        user_id=claims.sub,
        session_id=claims.session_id,
    )
    try:
        result = exchange_for_delegation(
            db,
            user_id=claims.sub,
            agent_identifier=body.actor,
            grant_type=body.grant_type,
            requested_token_type=body.requested_token_type,
            session_id=claims.session_id,
            scopes=scopes,
            settings=settings,
            tokens=tokens,
        )
    except Exception as exc:
        audit.log(
            db,
            ctx,
            action=Action.AUTH_DELEGATE,
            decision=Outcome.DENY,
            reason=getattr(exc, "code", "delegation_failed"),
            error=str(exc),
            details={"requested_agent": body.actor},
        )
        db.commit()
        raise

    from ...identity.agents import resolve_agent

    agent = resolve_agent(db, body.actor)
    ctx.agent_id = agent.id if agent else None
    audit.log(
        db,
        ctx,
        action=Action.AUTH_DELEGATE,
        decision=Outcome.ALLOW,
        reason="delegated",
        details={"agent": body.actor, "delegation_id": result.delegation_id},
    )
    db.commit()
    return TokenResponse(
        access_token=result.access_token,
        expires_in=result.expires_in,
        scope=result.scope,
        session_id=claims.session_id,
        issued_token_type=result.issued_token_type,
        delegation_id=result.delegation_id,
    )


@router.post("/introspect")
def introspect(
    body: IntrospectRequest,
    ctx: ContextDep,
    tokens: Annotated[TokenService, Depends(get_token_service)],
) -> dict[str, object]:
    """Inspect a gateway token. Callers may only introspect their own tokens."""
    try:
        claims = tokens.verify(body.token)
    except AuthenticationError:
        return {"active": False}

    owner = claims.sub == (ctx.user_id or ctx.agent_id or ctx.service_account_id)
    if not owner:
        return {"active": False}
    return {
        "active": True,
        "sub": claims.sub,
        "act": {"sub": claims.act_sub} if claims.act_sub else None,
        "persona": claims.persona.value,
        "aud": claims.audience,
        "iss": claims.issuer,
        "typ": claims.token_type,
        "scope": " ".join(claims.scopes),
        "exp": int(claims.expires_at.timestamp()),
        "iat": int(claims.issued_at.timestamp()),
    }


@router.post("/logout")
def logout(ctx: ContextDep, request: Request, db: DbDep) -> dict[str, str]:
    if ctx.session_id:
        revoke_session(db, ctx.session_id)
    get_audit(request).log(
        db, ctx, action=Action.SESSION_REVOKE, decision=Outcome.ALLOW, reason="logout"
    )
    db.commit()
    return {"status": "revoked"}


@router.get("/whoami", response_model=WhoAmIResponse)
def whoami(ctx: ContextDep, db: DbDep) -> WhoAmIResponse:
    from ..deps import _permissions_for

    permissions = _permissions_for(db, ctx)
    return WhoAmIResponse(
        request_id=ctx.request_id,
        persona=ctx.persona.value,
        user_id=ctx.user_id,
        agent_id=ctx.agent_id,
        service_account_id=ctx.service_account_id,
        execution_identity=ctx.execution_identity,
        delegated=ctx.is_delegated,
        scopes=list(ctx.scopes),
        permissions=sorted(permissions.allow) if permissions else [],
        denied=sorted(permissions.deny) if permissions else [],
    )


def _failure_record(*, request_id: str, action: str, reason: str, subject: str):
    from ...audit.events import AuditRecord

    return AuditRecord(
        action=action,
        decision=Outcome.DENY,
        request_id=request_id,
        reason=reason,
        details={"subject": subject},
    )
