"""Role and policy administration."""

from __future__ import annotations

from fastapi import APIRouter, Request

from ...audit.events import Action, Outcome
from ...authorization.policies import PolicyBundle
from ...authorization.rbac import get_role, list_roles, upsert_role
from ...errors import NotFoundError
from ...identity import agents as agents_svc
from ...identity import service_accounts as sa_svc
from ...identity import users as users_svc
from ..deps import AdminDep, DbDep, get_audit
from .schemas import AssignRolesRequest, RoleRequest, RoleResponse

router = APIRouter(prefix="/policy", tags=["policy"])


def _role_response(role) -> RoleResponse:
    return RoleResponse(
        name=role.name,
        description=role.description,
        allow=sorted(role.allowed()),
        deny=sorted(role.denied()),
    )


@router.get("/roles", response_model=list[RoleResponse])
def list_all_roles(_admin: AdminDep, db: DbDep) -> list[RoleResponse]:
    return [_role_response(r) for r in list_roles(db)]


@router.put("/roles", response_model=RoleResponse)
def put_role(body: RoleRequest, admin: AdminDep, db: DbDep, request: Request) -> RoleResponse:
    role = upsert_role(
        db, body.role, allow=body.allow, deny=body.deny, description=body.description
    )
    get_audit(request).log(
        db,
        admin,
        action=Action.ADMIN_CHANGE,
        decision=Outcome.ALLOW,
        reason="role.upsert",
        policy=role.name,
    )
    db.commit()
    return _role_response(role)


@router.get("/roles/{name}", response_model=RoleResponse)
def get_single_role(name: str, _admin: AdminDep, db: DbDep) -> RoleResponse:
    role = get_role(db, name)
    if role is None:
        raise NotFoundError(f"unknown role: {name}", code="unknown_role")
    return _role_response(role)


@router.post("/bundle", response_model=list[RoleResponse])
def apply_bundle(
    body: dict, admin: AdminDep, db: DbDep, request: Request
) -> list[RoleResponse]:
    """Apply a whole policy bundle (the JSON form of the YAML policy file)."""
    bundle = PolicyBundle.from_obj(body)
    roles = bundle.apply(db)
    get_audit(request).log(
        db,
        admin,
        action=Action.ADMIN_CHANGE,
        decision=Outcome.ALLOW,
        reason="policy.bundle",
        details={"roles": [r.name for r in roles]},
    )
    db.commit()
    return [_role_response(r) for r in roles]


@router.post("/users/{user_id}/roles", response_model=list[str])
def assign_user_roles(
    user_id: str, body: AssignRolesRequest, admin: AdminDep, db: DbDep, request: Request
) -> list[str]:
    user = users_svc.require_user(db, user_id)
    users_svc.assign_roles(db, user, body.roles)
    get_audit(request).log(
        db,
        admin,
        action=Action.ADMIN_CHANGE,
        decision=Outcome.ALLOW,
        reason="user.roles",
        details={"user": user.id, "roles": body.roles},
    )
    db.commit()
    return [r.name for r in user.roles]


@router.post("/agents/{agent_id}/roles", response_model=list[str])
def assign_agent_roles(
    agent_id: str, body: AssignRolesRequest, admin: AdminDep, db: DbDep, request: Request
) -> list[str]:
    agent = agents_svc.require_agent(db, agent_id)
    roles = []
    for name in body.roles:
        role = get_role(db, name)
        if role is None:
            raise NotFoundError(f"unknown role: {name}", code="unknown_role")
        roles.append(role)
    agent.roles = roles
    db.flush()
    get_audit(request).log(
        db,
        admin,
        action=Action.ADMIN_CHANGE,
        decision=Outcome.ALLOW,
        reason="agent.roles",
        details={"agent": agent.id, "roles": body.roles},
    )
    db.commit()
    return [r.name for r in agent.roles]


@router.post("/service-accounts/{sa_id}/roles", response_model=list[str])
def assign_sa_roles(
    sa_id: str, body: AssignRolesRequest, admin: AdminDep, db: DbDep, request: Request
) -> list[str]:
    sa = sa_svc.require_service_account(db, sa_id)
    roles = []
    for name in body.roles:
        role = get_role(db, name)
        if role is None:
            raise NotFoundError(f"unknown role: {name}", code="unknown_role")
        roles.append(role)
    sa.roles = roles
    db.flush()
    get_audit(request).log(
        db,
        admin,
        action=Action.ADMIN_CHANGE,
        decision=Outcome.ALLOW,
        reason="service_account.roles",
        details={"service_account": sa.id, "roles": body.roles},
    )
    db.commit()
    return [r.name for r in sa.roles]
