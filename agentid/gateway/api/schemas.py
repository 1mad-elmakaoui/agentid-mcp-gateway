"""Request and response models for the gateway API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import AliasChoices, BaseModel, EmailStr, Field

from ...models import AgentKind, CredentialType, IdentityType


# -- auth ----------------------------------------------------------------
class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str | None = None
    session_id: str | None = None
    issued_token_type: str | None = None
    delegation_id: str | None = None


class TokenExchangeRequest(BaseModel):
    """RFC 8693 token exchange, narrowed to what AgentID supports."""

    grant_type: str = "urn:ietf:params:oauth:grant-type:token-exchange"
    subject_token: str
    subject_token_type: str = "urn:ietf:params:oauth:token-type:jwt"
    #: The agent that will act — id or name. RFC 8693 calls this the actor.
    actor: str = Field(
        ..., validation_alias=AliasChoices("actor", "actor_token", "agent")
    )
    requested_token_type: str = "urn:ietf:params:oauth:token-type:jwt"
    scope: str | None = None

    model_config = {"populate_by_name": True}


class IntrospectRequest(BaseModel):
    token: str


class WhoAmIResponse(BaseModel):
    request_id: str
    persona: str
    user_id: str | None = None
    agent_id: str | None = None
    service_account_id: str | None = None
    execution_identity: str
    delegated: bool
    scopes: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    denied: list[str] = Field(default_factory=list)


# -- identity ------------------------------------------------------------
class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str | None = None
    display_name: str | None = None
    roles: list[str] = Field(default_factory=list)


class UserResponse(BaseModel):
    id: str
    email: str
    display_name: str | None = None
    is_active: bool
    roles: list[str] = Field(default_factory=list)


class CreateAgentRequest(BaseModel):
    name: str
    kind: AgentKind = AgentKind.DELEGATED
    description: str | None = None
    owner_user_id: str | None = None
    roles: list[str] = Field(default_factory=list)


class AgentResponse(BaseModel):
    id: str
    name: str
    kind: AgentKind
    description: str | None = None
    owner_user_id: str | None = None
    is_active: bool
    roles: list[str] = Field(default_factory=list)


class CreateServiceAccountRequest(BaseModel):
    name: str
    description: str | None = None
    roles: list[str] = Field(default_factory=list)


class ServiceAccountResponse(BaseModel):
    id: str
    name: str
    description: str | None = None
    is_active: bool
    roles: list[str] = Field(default_factory=list)


class GrantAgentRequest(BaseModel):
    agent: str
    scopes: str | None = None


class GrantServiceAccountRequest(BaseModel):
    grantee_type: IdentityType
    grantee_id: str


class CreateApiKeyRequest(BaseModel):
    name: str
    owner_type: IdentityType
    owner_id: str
    ttl_seconds: int | None = None


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    owner_type: IdentityType
    owner_id: str
    expires_at: datetime | None = None
    #: Returned exactly once, at creation.
    api_key: str | None = None


# -- registry ------------------------------------------------------------
class RegisterServerRequest(BaseModel):
    name: str
    endpoint: str
    description: str | None = None
    credential_type: CredentialType = CredentialType.NONE
    audience: str | None = None
    enabled: bool = True
    capabilities: dict[str, Any] = Field(default_factory=dict)


class RegisterToolRequest(BaseModel):
    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    required_permission: str | None = None
    tags: list[str] = Field(default_factory=list)
    requires_service_account: bool = False
    default_service_account_id: str | None = None
    enabled: bool = True


class StoreCredentialRequest(BaseModel):
    credential_type: CredentialType
    #: Secret payload, e.g. ``{"api_key": "..."}`` or ``{"access_token": "..."}``.
    payload: dict[str, Any]
    owner_type: IdentityType | None = None
    owner_id: str | None = None
    expires_at: datetime | None = None


# -- policy --------------------------------------------------------------
class RoleRequest(BaseModel):
    role: str
    description: str | None = None
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)


class RoleResponse(BaseModel):
    name: str
    description: str | None = None
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)


class AssignRolesRequest(BaseModel):
    roles: list[str]


# -- mcp -----------------------------------------------------------------
class ToolSearchRequest(BaseModel):
    query: str = ""
    servers: list[str] | None = None
    limit: int = Field(default=20, ge=1, le=200)
    include_schema: bool = True


class CallToolRequest(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    server: str | None = None
    #: Optional explicit service account to execute through.
    service_account: str | None = None
    #: Downstream resource identifier, recorded in the audit trail.
    resource: str | None = None


class CallToolResponse(BaseModel):
    request_id: str
    tool: str
    server: str
    decision: str
    execution_identity: str
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    latency_ms: int = 0
