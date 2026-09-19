"""Pydantic schemas for registry payloads (API + import/export)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..models import CredentialType, McpServer, Tool


class ToolSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    qualified_name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    required_permission: str | None = None
    tags: list[str] = Field(default_factory=list)
    requires_service_account: bool = False
    enabled: bool = True

    @classmethod
    def from_model(cls, tool: Tool) -> ToolSchema:
        return cls(
            name=tool.name,
            qualified_name=tool.qualified_name,
            description=tool.description,
            input_schema=tool.input_schema,
            required_permission=tool.permission,
            tags=list(tool.tags or []),
            requires_service_account=tool.requires_service_account,
            enabled=tool.enabled,
        )


class ServerSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: str | None = None
    endpoint: str
    credential_type: CredentialType
    audience: str | None = None
    enabled: bool = True
    capabilities: dict[str, Any] = Field(default_factory=dict)
    tools: list[ToolSchema] = Field(default_factory=list)

    @classmethod
    def from_model(cls, server: McpServer, *, include_tools: bool = True) -> ServerSchema:
        return cls(
            id=server.id,
            name=server.name,
            description=server.description,
            endpoint=server.endpoint,
            credential_type=server.credential_type,
            audience=server.audience,
            enabled=server.enabled,
            capabilities=server.capabilities or {},
            tools=[ToolSchema.from_model(t) for t in server.tools] if include_tools else [],
        )


class ServerRegistration(BaseModel):
    name: str
    endpoint: str
    description: str | None = None
    credential_type: CredentialType = CredentialType.NONE
    audience: str | None = None
    enabled: bool = True
    capabilities: dict[str, Any] = Field(default_factory=dict)


class ToolRegistration(BaseModel):
    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    required_permission: str | None = None
    tags: list[str] = Field(default_factory=list)
    requires_service_account: bool = False
    default_service_account_id: str | None = None
    enabled: bool = True
