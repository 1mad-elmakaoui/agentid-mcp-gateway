"""Demo seed data.

Creates the cast used throughout the docs, tests and the demo script:

    Imad (developer)  --authorizes-->  coding-agent      (delegated)
    security-agent    (autonomous)     --executes as-->  security-service-account
    production-deployer                (service account nobody may borrow yet)

Idempotent: running it twice leaves the same world.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session as DbSession

from ..authorization.policies import PolicyBundle
from ..credentials.api_keys import make_payload as api_key_payload
from ..credentials.manager import SERVER_DEFAULT_OWNER, CredentialManager
from ..identity import agents as agents_svc
from ..identity import api_keys as api_keys_svc
from ..identity import service_accounts as sa_svc
from ..identity import users as users_svc
from ..models import AgentKind, CredentialType, IdentityType
from ..registry import servers as servers_svc
from ..registry import tools as tools_svc

#: Where the default policy bundle is looked for, in order. The repository
#: root comes first (development, and the Docker image, which copies the tree);
#: the working directory covers an installed package run from a project dir.
POLICY_SEARCH_PATHS = (
    Path(__file__).resolve().parents[2] / "policies" / "default.yaml",
    Path(__file__).resolve().parent / "policies" / "default.yaml",
    Path.cwd() / "policies" / "default.yaml",
)

DEMO_PASSWORD = "demo-password"


def default_policy_file() -> Path:
    for candidate in POLICY_SEARCH_PATHS:
        if candidate.is_file():
            return candidate
    searched = ", ".join(str(p) for p in POLICY_SEARCH_PATHS)
    raise FileNotFoundError(
        f"no default policy bundle found; looked in: {searched}. "
        "Pass --policy explicitly or set AGENTID_POLICY_FILE."
    )


@dataclass(slots=True)
class SeedResult:
    users: dict[str, Any]
    agents: dict[str, Any]
    service_accounts: dict[str, Any]
    servers: dict[str, Any]
    api_keys: dict[str, str]

    def summary(self) -> str:
        return (
            f"{len(self.users)} users, {len(self.agents)} agents, "
            f"{len(self.service_accounts)} service accounts, {len(self.servers)} servers"
        )


TOOL_CATALOG: dict[str, list[dict[str, Any]]] = {
    "github": [
        {
            "name": "create_issue",
            "description": "Create an issue in a repository",
            "tags": ["github", "issue", "write"],
            "input_schema": {
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "title": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["repo", "title"],
            },
        },
        {
            "name": "get_issue",
            "description": "Read a single issue by number",
            "tags": ["github", "issue", "read"],
            "input_schema": {
                "type": "object",
                "properties": {"number": {"type": "integer"}},
                "required": ["number"],
            },
        },
        {
            "name": "list_issues",
            "description": "List issues, optionally filtered by repository",
            "tags": ["github", "issue", "read"],
            "input_schema": {"type": "object", "properties": {"repo": {"type": "string"}}},
        },
        {
            "name": "search_repository",
            "description": "Search repositories by name or description",
            "tags": ["github", "search", "read"],
            "input_schema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    ],
    "database": [
        {
            "name": "query",
            "description": "Read rows from a table",
            "tags": ["database", "sql", "read"],
            "input_schema": {
                "type": "object",
                "properties": {"table": {"type": "string"}, "limit": {"type": "integer"}},
                "required": ["table"],
            },
        },
        {
            "name": "list_tables",
            "description": "List the tables this database exposes",
            "tags": ["database", "schema", "read"],
            "input_schema": {"type": "object", "properties": {}},
        },
        {
            "name": "describe_table",
            "description": "Describe a table's columns",
            "tags": ["database", "schema", "read"],
            "input_schema": {
                "type": "object",
                "properties": {"table": {"type": "string"}},
                "required": ["table"],
            },
        },
    ],
    "kubernetes": [
        {
            "name": "get_logs",
            "description": "Read logs for a pod",
            "tags": ["kubernetes", "logs", "read"],
            "input_schema": {
                "type": "object",
                "properties": {"namespace": {"type": "string"}, "pod": {"type": "string"}},
            },
            "requires_service_account": True,
        },
        {
            "name": "list_pods",
            "description": "List pods in a namespace",
            "tags": ["kubernetes", "read"],
            "input_schema": {"type": "object", "properties": {"namespace": {"type": "string"}}},
            "requires_service_account": True,
        },
        {
            "name": "delete_namespace",
            "description": "Delete a namespace (destructive)",
            "tags": ["kubernetes", "destructive", "write"],
            "input_schema": {
                "type": "object",
                "properties": {"namespace": {"type": "string"}},
                "required": ["namespace"],
            },
            "requires_service_account": True,
        },
    ],
}

SERVER_ENDPOINTS = {
    "github": "http://github-mcp:8001",
    "database": "http://postgres-mcp:8002",
    "kubernetes": "http://kubernetes-mcp:8003",
}

SERVER_AUDIENCES = {
    "github": "agentid-mcp:github",
    "database": "agentid-mcp:database",
    "kubernetes": "agentid-mcp:kubernetes",
}


def seed(
    db: DbSession,
    *,
    policy_file: Path | str | None = None,
    endpoints: dict[str, str] | None = None,
    credentials: CredentialManager | None = None,
    issue_api_keys: bool = True,
) -> SeedResult:
    endpoints = {**SERVER_ENDPOINTS, **(endpoints or {})}
    PolicyBundle.load(policy_file or default_policy_file()).apply(db)

    users = {
        "imad": _user(db, "imad@example.com", "Imad", ["developer"]),
        "ops": _user(db, "ops@example.com", "Ops Engineer", ["operator"]),
        "admin": _user(db, "admin@example.com", "Platform Admin", ["admin"]),
    }

    agents = {
        "coding-agent": _agent(
            db,
            "coding-agent",
            AgentKind.DELEGATED,
            "Interactive coding assistant",
            ["coding-agent"],
        ),
        "security-agent": _agent(
            db,
            "security-agent",
            AgentKind.AUTONOMOUS,
            "Autonomous overnight security scanner",
            ["security-agent"],
        ),
    }

    service_accounts = {
        "security": _service_account(
            db, "security-service-account", "Runs autonomous security checks", ["security-agent"]
        ),
        "reporting": _service_account(
            db, "reporting-service-account", "Read-only reporting jobs", ["reporting"]
        ),
        "deployer": _service_account(
            db, "production-deployer", "Privileged production changes", ["production-deployer"]
        ),
    }

    # Imad authorizes the coding agent to act on his behalf. Nobody has been
    # granted the production deployer: that is the denial the demo exercises.
    agents_svc.grant_agent_to_user(
        db, user_id=users["imad"].id, agent_id=agents["coding-agent"].id
    )
    agents_svc.grant_agent_to_user(
        db, user_id=users["admin"].id, agent_id=agents["coding-agent"].id
    )
    sa_svc.grant_service_account(
        db,
        grantee_type=IdentityType.AGENT,
        grantee_id=agents["security-agent"].id,
        service_account_id=service_accounts["security"].id,
    )
    sa_svc.grant_service_account(
        db,
        grantee_type=IdentityType.USER,
        grantee_id=users["ops"].id,
        service_account_id=service_accounts["security"].id,
    )

    servers = {}
    for name, tools in TOOL_CATALOG.items():
        server = servers_svc.get_server_by_name(db, name)
        if server is None:
            server = servers_svc.register_server(
                db,
                name=name,
                endpoint=endpoints[name],
                description=f"{name} MCP server",
                credential_type=CredentialType.API_KEY,
                audience=SERVER_AUDIENCES[name],
            )
        servers[name] = server
        for spec in tools:
            qualified = f"{name}.{spec['name']}"
            if tools_svc.get_tool(db, qualified) is not None:
                continue
            tools_svc.register_tool(
                db,
                server=server,
                name=spec["name"],
                description=spec["description"],
                input_schema=spec.get("input_schema", {}),
                tags=spec.get("tags", []),
                requires_service_account=spec.get("requires_service_account", False),
                default_service_account_id=(
                    service_accounts["security"].id
                    if spec.get("requires_service_account")
                    else None
                ),
            )

    manager = credentials or CredentialManager()
    for name, server in servers.items():
        manager.store(
            db,
            server=server,
            credential_type=CredentialType.API_KEY,
            payload=api_key_payload(f"downstream-{name}-secret"),
            owner_type=SERVER_DEFAULT_OWNER,
            owner_id=server.id,
        )

    api_keys: dict[str, str] = {}
    if issue_api_keys:
        api_keys["security-agent"] = api_keys_svc.issue_api_key(
            db,
            name="security-agent nightly key",
            owner_type=IdentityType.AGENT,
            owner_id=agents["security-agent"].id,
        ).plaintext
        api_keys["reporting-service-account"] = api_keys_svc.issue_api_key(
            db,
            name="reporting job key",
            owner_type=IdentityType.SERVICE_ACCOUNT,
            owner_id=service_accounts["reporting"].id,
        ).plaintext

    db.commit()
    return SeedResult(
        users=users,
        agents=agents,
        service_accounts=service_accounts,
        servers=servers,
        api_keys=api_keys,
    )


def _user(db: DbSession, email: str, name: str, roles: list[str]):
    existing = users_svc.get_user_by_email(db, email)
    if existing is not None:
        users_svc.assign_roles(db, existing, roles)
        return existing
    return users_svc.create_user(
        db, email=email, password=DEMO_PASSWORD, display_name=name, roles=roles
    )


def _agent(db: DbSession, name: str, kind: AgentKind, description: str, roles: list[str]):
    existing = agents_svc.get_agent_by_name(db, name)
    if existing is not None:
        return existing
    return agents_svc.create_agent(
        db, name=name, kind=kind, description=description, roles=roles
    )


def _service_account(db: DbSession, name: str, description: str, roles: list[str]):
    existing = sa_svc.get_service_account_by_name(db, name)
    if existing is not None:
        return existing
    return sa_svc.create_service_account(db, name=name, description=description, roles=roles)
