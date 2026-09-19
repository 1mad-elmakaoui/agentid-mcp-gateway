"""MCP registry administration and browsing."""

from __future__ import annotations

from fastapi import APIRouter, Request

from ...audit.events import Action, Outcome
from ...credentials.manager import SERVER_DEFAULT_OWNER
from ...registry import servers as servers_svc
from ...registry import tools as tools_svc
from ...registry.schemas import ServerSchema, ToolSchema
from ..deps import AdminDep, ContextDep, DbDep, get_audit, get_credential_manager
from .schemas import RegisterServerRequest, RegisterToolRequest, StoreCredentialRequest

router = APIRouter(prefix="/registry", tags=["registry"])


@router.get("/servers", response_model=list[ServerSchema])
def list_servers(_ctx: ContextDep, db: DbDep, enabled_only: bool = False) -> list[ServerSchema]:
    return [
        ServerSchema.from_model(s) for s in servers_svc.list_servers(db, enabled_only=enabled_only)
    ]


@router.post("/servers", response_model=ServerSchema, status_code=201)
def register_server(
    body: RegisterServerRequest, admin: AdminDep, db: DbDep, request: Request
) -> ServerSchema:
    server = servers_svc.register_server(
        db,
        name=body.name,
        endpoint=body.endpoint,
        description=body.description,
        credential_type=body.credential_type,
        audience=body.audience,
        enabled=body.enabled,
        capabilities=body.capabilities,
    )
    get_audit(request).log(
        db,
        admin,
        action=Action.ADMIN_CHANGE,
        decision=Outcome.ALLOW,
        reason="server.register",
        server=server.name,
    )
    db.commit()
    return ServerSchema.from_model(server)


@router.get("/servers/{name}", response_model=ServerSchema)
def get_server(name: str, _ctx: ContextDep, db: DbDep) -> ServerSchema:
    return ServerSchema.from_model(servers_svc.require_server(db, name))


@router.post("/servers/{name}/enabled", response_model=ServerSchema)
def set_server_enabled(
    name: str, enabled: bool, admin: AdminDep, db: DbDep, request: Request
) -> ServerSchema:
    server = servers_svc.set_enabled(db, name, enabled)
    get_audit(request).log(
        db,
        admin,
        action=Action.ADMIN_CHANGE,
        decision=Outcome.ALLOW,
        reason="server.enabled" if enabled else "server.disabled",
        server=server.name,
    )
    db.commit()
    return ServerSchema.from_model(server)


@router.delete("/servers/{name}")
def delete_server(name: str, admin: AdminDep, db: DbDep, request: Request) -> dict[str, str]:
    servers_svc.delete_server(db, name)
    get_audit(request).log(
        db,
        admin,
        action=Action.ADMIN_CHANGE,
        decision=Outcome.ALLOW,
        reason="server.delete",
        server=name,
    )
    db.commit()
    return {"status": "deleted"}


@router.post("/servers/{name}/tools", response_model=ToolSchema, status_code=201)
def register_tool(
    name: str, body: RegisterToolRequest, admin: AdminDep, db: DbDep, request: Request
) -> ToolSchema:
    server = servers_svc.require_server(db, name)
    tool = tools_svc.register_tool(
        db,
        server=server,
        name=body.name,
        description=body.description,
        input_schema=body.input_schema,
        required_permission=body.required_permission,
        tags=body.tags,
        requires_service_account=body.requires_service_account,
        default_service_account_id=body.default_service_account_id,
        enabled=body.enabled,
    )
    get_audit(request).log(
        db,
        admin,
        action=Action.ADMIN_CHANGE,
        decision=Outcome.ALLOW,
        reason="tool.register",
        server=server.name,
        tool=tool.qualified_name,
    )
    db.commit()
    return ToolSchema.from_model(tool)


@router.get("/tools", response_model=list[ToolSchema])
def list_tools(_admin: AdminDep, db: DbDep, server: str | None = None) -> list[ToolSchema]:
    """The raw catalog. Agents use ``/mcp/tools`` instead, which filters by
    permission — this endpoint is administrative on purpose."""
    return [ToolSchema.from_model(t) for t in tools_svc.list_tools(db, server=server)]


@router.delete("/tools/{qualified_name}")
def delete_tool(
    qualified_name: str, admin: AdminDep, db: DbDep, request: Request
) -> dict[str, str]:
    tools_svc.delete_tool(db, qualified_name)
    get_audit(request).log(
        db,
        admin,
        action=Action.ADMIN_CHANGE,
        decision=Outcome.ALLOW,
        reason="tool.delete",
        tool=qualified_name,
    )
    db.commit()
    return {"status": "deleted"}


@router.post("/servers/{name}/credentials", status_code=201)
def store_credential(
    name: str,
    body: StoreCredentialRequest,
    admin: AdminDep,
    db: DbDep,
    request: Request,
) -> dict[str, str]:
    """Store a downstream credential.

    The payload goes straight into the vault; no endpoint ever reads it back
    out (invariant 7), so the response carries only an identifier.
    """
    server = servers_svc.require_server(db, name)
    manager = get_credential_manager(request)
    record = manager.store(
        db,
        server=server,
        credential_type=body.credential_type,
        payload=body.payload,
        owner_type=body.owner_type or SERVER_DEFAULT_OWNER,
        owner_id=body.owner_id,
        expires_at=body.expires_at,
    )
    get_audit(request).log(
        db,
        admin,
        action=Action.ADMIN_CHANGE,
        decision=Outcome.ALLOW,
        reason="credential.store",
        server=server.name,
        details={"credential_id": record.id, "credential_type": body.credential_type.value},
    )
    db.commit()
    return {"credential_id": record.id, "status": "stored"}


@router.delete("/credentials/{credential_id}")
def delete_credential(
    credential_id: str, admin: AdminDep, db: DbDep, request: Request
) -> dict[str, str]:
    get_credential_manager(request).delete(db, credential_id)
    get_audit(request).log(
        db,
        admin,
        action=Action.ADMIN_CHANGE,
        decision=Outcome.ALLOW,
        reason="credential.delete",
        details={"credential_id": credential_id},
    )
    db.commit()
    return {"status": "deleted"}
