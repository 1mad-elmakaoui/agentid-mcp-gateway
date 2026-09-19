"""Example PostgreSQL MCP server.

Demonstrates resource-level authorization on a different axis from GitHub:
which *tables* an identity may read, and the fact that a write path exists but
is reserved for service accounts.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from ...sdk.server import GatewayClaims
from ..common import ResourceDenied, ToolSpec, build_server, text

AUDIENCE = "agentid-mcp:database"

_TABLES: dict[str, list[dict[str, Any]]] = {
    "public.users": [
        {"id": 1, "email": "imad@example.com", "role": "developer"},
        {"id": 2, "email": "ops@example.com", "role": "operator"},
    ],
    "public.deployments": [
        {"id": 10, "service": "backend", "version": "1.4.2", "status": "live"},
    ],
    "private.billing": [
        {"id": 100, "customer": "acme", "amount_cents": 250000},
    ],
}

#: Tables only a service account may touch.
RESTRICTED_TABLES = {"private.billing"}


def _require_readable(claims: GatewayClaims, table: str) -> None:
    if table not in _TABLES:
        raise ResourceDenied(f"unknown table: {table}", resource=table)
    if table in RESTRICTED_TABLES and not claims.service_account:
        raise ResourceDenied(
            f"{table} may only be read by a service account", resource=table
        )


def _query(claims: GatewayClaims, arguments: dict[str, Any]) -> dict[str, Any]:
    table = str(arguments.get("table", ""))
    limit = int(arguments.get("limit", 10))
    if not table:
        return text("table is required", is_error=True)
    _require_readable(claims, table)
    rows = _TABLES[table][:limit]
    header = f"{len(rows)} row(s) from {table} (as {claims.identity_chain()})"
    return text("\n".join([header, *[str(r) for r in rows]]))


def _list_tables(_claims: GatewayClaims, _arguments: dict[str, Any]) -> dict[str, Any]:
    return text("\n".join(sorted(_TABLES)))


def _describe_table(claims: GatewayClaims, arguments: dict[str, Any]) -> dict[str, Any]:
    table = str(arguments.get("table", ""))
    _require_readable(claims, table)
    rows = _TABLES[table]
    columns = sorted(rows[0].keys()) if rows else []
    return text(f"{table}: {', '.join(columns) or '(no columns)'}")


TOOLS = [
    ToolSpec(
        name="query",
        description="Read rows from a table",
        input_schema={
            "type": "object",
            "properties": {"table": {"type": "string"}, "limit": {"type": "integer"}},
            "required": ["table"],
        },
        handler=_query,
    ),
    ToolSpec(
        name="list_tables",
        description="List the tables this database exposes",
        input_schema={"type": "object", "properties": {}},
        handler=_list_tables,
    ),
    ToolSpec(
        name="describe_table",
        description="Describe a table's columns",
        input_schema={
            "type": "object",
            "properties": {"table": {"type": "string"}},
            "required": ["table"],
        },
        handler=_describe_table,
    ),
]


def create_app(secret: str | None = None) -> FastAPI:
    return build_server(title="PostgreSQL MCP", audience=AUDIENCE, tools=TOOLS, secret=secret)


app = create_app()
