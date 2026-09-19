"""Tool ranking, routing and the discovery filter."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session as DbSession

from agentid.authorization.engine import AuthorizationEngine
from agentid.context import RequestContext
from agentid.database.seed import SeedResult
from agentid.errors import NotFoundError
from agentid.gateway.mcp.discovery import discover
from agentid.gateway.mcp.router import resolve_route
from agentid.models import Persona
from agentid.registry.tools import require_tool, score_tool, search_tools


def ctx_for(seeded: SeedResult, *, user: str = "imad", agent: str | None = None):
    return RequestContext(
        request_id="req_discover",
        persona=Persona.USER,
        user_id=seeded.users[user].id,
        agent_id=seeded.agents[agent].id if agent else None,
        scopes=("mcp:tools",),
    )


def test_exact_name_outranks_partial(db: DbSession, seeded: SeedResult) -> None:
    tool = require_tool(db, "github.create_issue")
    assert score_tool(tool, "github.create_issue") == 1.0
    assert score_tool(tool, "create_issue") == 1.0
    assert score_tool(tool, "issue") > 0
    assert score_tool(tool, "kubernetes") == 0.0


def test_search_matches_description_and_tags(db: DbSession, seeded: SeedResult) -> None:
    matches = search_tools(db, query="read rows from a table", limit=5)
    assert matches[0].tool.qualified_name == "database.query"


def test_search_respects_the_permitted_set(db: DbSession, seeded: SeedResult) -> None:
    matches = search_tools(db, query="issue", permitted={"github.get_issue"})
    assert {m.tool.qualified_name for m in matches} == {"github.get_issue"}


def test_empty_permitted_set_returns_nothing(db: DbSession, seeded: SeedResult) -> None:
    assert search_tools(db, query="issue", permitted=set()) == []


def test_discover_filters_and_counts(db: DbSession, seeded: SeedResult, settings) -> None:
    engine = AuthorizationEngine(settings)
    result = discover(db, ctx_for(seeded), engine=engine, limit=100)
    names = {m.tool.qualified_name for m in result.matches}

    assert "github.create_issue" in names
    assert not any(n.startswith("kubernetes.") for n in names)
    assert result.filtered_out == 3  # the three kubernetes tools


def test_discovery_never_names_what_it_filtered(
    db: DbSession, seeded: SeedResult, settings
) -> None:
    result = discover(db, ctx_for(seeded), engine=AuthorizationEngine(settings), limit=100)
    payload = str(result.to_dict())
    assert "delete_namespace" not in payload


def test_router_resolves_a_qualified_name(db: DbSession, seeded: SeedResult) -> None:
    route = resolve_route(db, "github.create_issue")
    assert route.server.name == "github"
    assert route.downstream_name == "create_issue"
    assert route.url.endswith("/mcp")


def test_router_accepts_a_server_hint(db: DbSession, seeded: SeedResult) -> None:
    route = resolve_route(db, "create_issue", server_hint="github")
    assert route.qualified_name == "github.create_issue"


def test_router_rejects_a_mismatched_hint(db: DbSession, seeded: SeedResult) -> None:
    with pytest.raises(NotFoundError):
        resolve_route(db, "github.create_issue", server_hint="database")


def test_router_rejects_an_unqualified_name(db: DbSession, seeded: SeedResult) -> None:
    with pytest.raises(NotFoundError) as exc:
        resolve_route(db, "create_issue")
    assert exc.value.code == "unqualified_tool"
