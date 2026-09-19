"""Identity administration: users, agents, service accounts and grants."""

from __future__ import annotations

from fastapi import APIRouter, Request

from ...audit.events import Action, Outcome
from ...identity import agents as agents_svc
from ...identity import api_keys as api_keys_svc
from ...identity import service_accounts as sa_svc
from ...identity import users as users_svc
from ...models import IdentityType
from ..deps import AdminDep, ContextDep, DbDep, get_audit
from .schemas import (
    AgentResponse,
    ApiKeyResponse,
    CreateAgentRequest,
    CreateApiKeyRequest,
    CreateServiceAccountRequest,
    CreateUserRequest,
    GrantAgentRequest,
    GrantServiceAccountRequest,
    ServiceAccountResponse,
    UserResponse,
)

router = APIRouter(prefix="/identity", tags=["identity"])


def _user_response(user) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        is_active=user.is_active,
        roles=[r.name for r in user.roles],
    )


def _agent_response(agent) -> AgentResponse:
    return AgentResponse(
        id=agent.id,
        name=agent.name,
        kind=agent.kind,
        description=agent.description,
        owner_user_id=agent.owner_user_id,
        is_active=agent.is_active,
        roles=[r.name for r in agent.roles],
    )


def _sa_response(sa) -> ServiceAccountResponse:
    return ServiceAccountResponse(
        id=sa.id,
        name=sa.name,
        description=sa.description,
        is_active=sa.is_active,
        roles=[r.name for r in sa.roles],
    )


def _audit_admin(request: Request, db, ctx, *, target: str, change: str) -> None:
    get_audit(request).log(
        db,
        ctx,
        action=Action.ADMIN_CHANGE,
        decision=Outcome.ALLOW,
        reason=change,
        details={"target": target},
    )


# -- users ---------------------------------------------------------------
@router.get("/users", response_model=list[UserResponse])
def list_users(_admin: AdminDep, db: DbDep) -> list[UserResponse]:
    return [_user_response(u) for u in users_svc.list_users(db)]


@router.post("/users", response_model=UserResponse, status_code=201)
def create_user(
    body: CreateUserRequest, admin: AdminDep, db: DbDep, request: Request
) -> UserResponse:
    user = users_svc.create_user(
        db,
        email=str(body.email),
        password=body.password,
        display_name=body.display_name,
        roles=body.roles or None,
    )
    _audit_admin(request, db, admin, target=user.id, change="user.create")
    db.commit()
    return _user_response(user)


@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(user_id: str, _admin: AdminDep, db: DbDep) -> UserResponse:
    return _user_response(users_svc.require_user(db, user_id))


@router.post("/users/{user_id}/agents", status_code=201)
def grant_agent(
    user_id: str, body: GrantAgentRequest, admin: AdminDep, db: DbDep, request: Request
) -> dict[str, str]:
    user = users_svc.require_user(db, user_id)
    agent = agents_svc.require_agent(db, body.agent)
    agents_svc.grant_agent_to_user(
        db, user_id=user.id, agent_id=agent.id, scopes=body.scopes
    )
    _audit_admin(request, db, admin, target=f"{user.id}->{agent.id}", change="grant.agent")
    db.commit()
    return {"user_id": user.id, "agent_id": agent.id, "status": "granted"}


@router.delete("/users/{user_id}/agents/{agent_id}")
def revoke_agent(
    user_id: str, agent_id: str, admin: AdminDep, db: DbDep, request: Request
) -> dict[str, str]:
    agent = agents_svc.require_agent(db, agent_id)
    agents_svc.revoke_agent_from_user(db, user_id=user_id, agent_id=agent.id)
    _audit_admin(request, db, admin, target=f"{user_id}->{agent.id}", change="revoke.agent")
    db.commit()
    return {"status": "revoked"}


@router.get("/me/agents", response_model=list[AgentResponse])
def my_agents(ctx: ContextDep, db: DbDep) -> list[AgentResponse]:
    """The agents the calling user has authorized to act on their behalf."""
    if not ctx.user_id:
        return []
    return [_agent_response(a) for a in agents_svc.list_user_agents(db, ctx.user_id)]


# -- agents --------------------------------------------------------------
@router.get("/agents", response_model=list[AgentResponse])
def list_agents(_admin: AdminDep, db: DbDep) -> list[AgentResponse]:
    return [_agent_response(a) for a in agents_svc.list_agents(db)]


@router.post("/agents", response_model=AgentResponse, status_code=201)
def create_agent(
    body: CreateAgentRequest, admin: AdminDep, db: DbDep, request: Request
) -> AgentResponse:
    agent = agents_svc.create_agent(
        db,
        name=body.name,
        kind=body.kind,
        description=body.description,
        owner_user_id=body.owner_user_id,
        roles=body.roles or None,
    )
    _audit_admin(request, db, admin, target=agent.id, change="agent.create")
    db.commit()
    return _agent_response(agent)


@router.get("/agents/{agent_id}", response_model=AgentResponse)
def get_agent(agent_id: str, _admin: AdminDep, db: DbDep) -> AgentResponse:
    return _agent_response(agents_svc.require_agent(db, agent_id))


# -- service accounts ----------------------------------------------------
@router.get("/service-accounts", response_model=list[ServiceAccountResponse])
def list_service_accounts(_admin: AdminDep, db: DbDep) -> list[ServiceAccountResponse]:
    return [_sa_response(s) for s in sa_svc.list_service_accounts(db)]


@router.post("/service-accounts", response_model=ServiceAccountResponse, status_code=201)
def create_service_account(
    body: CreateServiceAccountRequest, admin: AdminDep, db: DbDep, request: Request
) -> ServiceAccountResponse:
    sa = sa_svc.create_service_account(
        db, name=body.name, description=body.description, roles=body.roles or None
    )
    _audit_admin(request, db, admin, target=sa.id, change="service_account.create")
    db.commit()
    return _sa_response(sa)


@router.post("/service-accounts/{sa_id}/grants", status_code=201)
def grant_service_account(
    sa_id: str,
    body: GrantServiceAccountRequest,
    admin: AdminDep,
    db: DbDep,
    request: Request,
) -> dict[str, str]:
    """Authorize a user or agent to execute through this service account."""
    sa = sa_svc.require_service_account(db, sa_id)
    sa_svc.grant_service_account(
        db,
        grantee_type=body.grantee_type,
        grantee_id=body.grantee_id,
        service_account_id=sa.id,
    )
    _audit_admin(
        request, db, admin, target=f"{body.grantee_id}->{sa.id}", change="grant.service_account"
    )
    db.commit()
    return {"service_account_id": sa.id, "grantee_id": body.grantee_id, "status": "granted"}


@router.delete("/service-accounts/{sa_id}/grants/{grantee_id}")
def revoke_service_account_grant(
    sa_id: str,
    grantee_id: str,
    grantee_type: IdentityType,
    admin: AdminDep,
    db: DbDep,
    request: Request,
) -> dict[str, str]:
    sa = sa_svc.require_service_account(db, sa_id)
    sa_svc.revoke_service_account(
        db, grantee_type=grantee_type, grantee_id=grantee_id, service_account_id=sa.id
    )
    _audit_admin(
        request, db, admin, target=f"{grantee_id}->{sa.id}", change="revoke.service_account"
    )
    db.commit()
    return {"status": "revoked"}


# -- api keys ------------------------------------------------------------
@router.post("/api-keys", response_model=ApiKeyResponse, status_code=201)
def create_api_key(
    body: CreateApiKeyRequest, admin: AdminDep, db: DbDep, request: Request
) -> ApiKeyResponse:
    """Issue a machine credential. The plaintext is shown exactly once."""
    issued = api_keys_svc.issue_api_key(
        db,
        name=body.name,
        owner_type=body.owner_type,
        owner_id=body.owner_id,
        ttl_seconds=body.ttl_seconds,
    )
    _audit_admin(request, db, admin, target=issued.record.id, change="api_key.create")
    db.commit()
    return ApiKeyResponse(
        id=issued.record.id,
        name=issued.record.name,
        owner_type=issued.record.owner_type,
        owner_id=issued.record.owner_id,
        expires_at=issued.record.expires_at,
        api_key=issued.plaintext,
    )


@router.get("/api-keys", response_model=list[ApiKeyResponse])
def list_api_keys(_admin: AdminDep, db: DbDep, owner_id: str | None = None) -> list[ApiKeyResponse]:
    return [
        ApiKeyResponse(
            id=key.id,
            name=key.name,
            owner_type=key.owner_type,
            owner_id=key.owner_id,
            expires_at=key.expires_at,
            api_key=None,  # never re-disclosed
        )
        for key in api_keys_svc.list_api_keys(db, owner_id=owner_id)
    ]


@router.delete("/api-keys/{api_key_id}")
def revoke_api_key(
    api_key_id: str, admin: AdminDep, db: DbDep, request: Request
) -> dict[str, str]:
    api_keys_svc.revoke_api_key(db, api_key_id)
    _audit_admin(request, db, admin, target=api_key_id, change="api_key.revoke")
    db.commit()
    return {"status": "revoked"}
