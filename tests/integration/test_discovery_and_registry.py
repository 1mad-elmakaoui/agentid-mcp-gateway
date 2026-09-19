"""Tool discovery, the registry API and admin boundaries."""

from __future__ import annotations

import httpx

from agentid.database.seed import SeedResult
from tests.conftest import bearer, delegate, login


async def test_discovery_only_returns_permitted_tools(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    token = await login(client, "imad@example.com")
    response = await client.get("/mcp/tools", headers=bearer(token), params={"limit": 100})
    body = response.json()
    names = {t["name"] for t in body["tools"]}

    assert "github.create_issue" in names
    # A developer may not touch the cluster, so those tools do not exist for them.
    assert not any(n.startswith("kubernetes.") for n in names)
    assert body["filtered_out"] > 0


async def test_discovery_ranks_by_intent(client: httpx.AsyncClient, seeded: SeedResult) -> None:
    token = await login(client, "imad@example.com")
    response = await client.post(
        "/mcp/tools/search",
        headers=bearer(token),
        json={"query": "create a github issue", "limit": 5},
    )
    tools = response.json()["tools"]
    assert tools, "expected at least one match"
    assert tools[0]["name"] == "github.create_issue"
    assert tools[0]["input_schema"]["required"] == ["repo", "title"]


async def test_discovery_can_omit_schemas(client: httpx.AsyncClient, seeded: SeedResult) -> None:
    token = await login(client, "imad@example.com")
    response = await client.post(
        "/mcp/tools/search",
        headers=bearer(token),
        json={"query": "issue", "include_schema": False},
    )
    assert all("input_schema" not in t for t in response.json()["tools"])


async def test_delegated_discovery_is_the_intersection(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    admin_token = await login(client, "admin@example.com")
    delegated = await delegate(client, admin_token, "coding-agent")

    admin_tools = (
        await client.get("/mcp/tools", headers=bearer(admin_token), params={"limit": 100})
    ).json()["tools"]
    agent_tools = (
        await client.get("/mcp/tools", headers=bearer(delegated), params={"limit": 100})
    ).json()["tools"]

    admin_names = {t["name"] for t in admin_tools}
    agent_names = {t["name"] for t in agent_tools}
    assert agent_names < admin_names, "the delegated view must be a strict subset"
    assert not any(n.startswith("kubernetes.") for n in agent_names)


async def test_autonomous_agent_sees_only_its_own_tools(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    response = await client.get(
        "/mcp/tools",
        headers={"X-API-Key": seeded.api_keys["security-agent"]},
        params={"limit": 100},
    )
    names = {t["name"] for t in response.json()["tools"]}
    assert "kubernetes.get_logs" in names
    assert "kubernetes.delete_namespace" not in names
    assert not any(n.startswith("github.") for n in names)


async def test_servers_endpoint_lists_only_reachable_servers(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    token = await login(client, "imad@example.com")
    body = (await client.get("/mcp/servers", headers=bearer(token))).json()
    names = {s["name"] for s in body["servers"]}
    assert names == {"github", "database"}


async def test_registry_writes_require_admin(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    developer = await login(client, "imad@example.com")
    response = await client.post(
        "/registry/servers",
        headers=bearer(developer),
        json={"name": "sneaky", "endpoint": "http://sneaky.test"},
    )
    assert response.status_code == 403
    assert response.json()["error"] == "missing_permission"


async def test_admin_can_register_a_server_and_tool(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    admin = await login(client, "admin@example.com")
    created = await client.post(
        "/registry/servers",
        headers=bearer(admin),
        json={
            "name": "jira",
            "endpoint": "http://jira-mcp.test",
            "audience": "agentid-mcp:jira",
        },
    )
    assert created.status_code == 201

    tool = await client.post(
        "/registry/servers/jira/tools",
        headers=bearer(admin),
        json={"name": "create_ticket", "description": "Open a ticket", "tags": ["jira"]},
    )
    assert tool.status_code == 201
    assert tool.json()["qualified_name"] == "jira.create_ticket"


async def test_raw_catalog_is_admin_only(client: httpx.AsyncClient, seeded: SeedResult) -> None:
    developer = await login(client, "imad@example.com")
    assert (await client.get("/registry/tools", headers=bearer(developer))).status_code == 403

    admin = await login(client, "admin@example.com")
    catalog = await client.get("/registry/tools", headers=bearer(admin))
    assert catalog.status_code == 200
    assert len(catalog.json()) >= 10


async def test_stored_credentials_are_never_returned(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    admin = await login(client, "admin@example.com")
    response = await client.post(
        "/registry/servers/github/credentials",
        headers=bearer(admin),
        json={"credential_type": "api_key", "payload": {"api_key": "ghp_supersecret"}},
    )
    assert response.status_code == 201
    assert "ghp_supersecret" not in response.text
    assert set(response.json()) == {"credential_id", "status"}

    # No read path exists at all.
    server = await client.get("/registry/servers/github", headers=bearer(admin))
    assert "ghp_supersecret" not in server.text


async def test_policy_bundle_can_be_applied(client: httpx.AsyncClient, seeded: SeedResult) -> None:
    admin = await login(client, "admin@example.com")
    response = await client.post(
        "/policy/bundle",
        headers=bearer(admin),
        json={
            "roles": [
                {"role": "auditor", "allow": ["database.query"], "deny": ["database.drop"]}
            ]
        },
    )
    assert response.status_code == 200
    assert response.json()[0] == {
        "name": "auditor",
        "description": None,
        "allow": ["database.query"],
        "deny": ["database.drop"],
    }
