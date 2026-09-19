"""The end-to-end demo: allow, deny, and delegation with a full audit trail.

    User -> AgentID -> GitHub MCP -> GitHub
    Unauthorized agent -> AgentID -> 403
"""

from __future__ import annotations

import httpx
import pytest

from agentid.database.seed import SeedResult
from agentid.servers.github import allow_write
from tests.conftest import bearer, delegate, login

pytestmark = pytest.mark.e2e


async def test_user_through_agent_to_github(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    allow_write("company/backend", seeded.users["imad"].id)

    user_token = await login(client, "imad@example.com")
    agent_token = await delegate(client, user_token, "coding-agent")

    response = await client.post(
        "/mcp/call",
        headers=bearer(agent_token),
        json={
            "tool": "github.create_issue",
            "arguments": {"repo": "company/backend", "title": "Flaky test in CI"},
            "resource": "company/backend",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "allow"
    assert body["server"] == "github"
    assert body["result"]["isError"] is False
    assert "Created issue #1" in body["result"]["content"][0]["text"]
    assert body["execution_identity"] == seeded.users["imad"].id


async def test_denied_tool_returns_403_and_never_reaches_the_server(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    user_token = await login(client, "imad@example.com")
    agent_token = await delegate(client, user_token, "coding-agent")

    response = await client.post(
        "/mcp/call",
        headers=bearer(agent_token),
        json={"tool": "kubernetes.delete_namespace", "arguments": {"namespace": "staging"}},
    )
    assert response.status_code == 403
    body = response.json()
    assert body["error"] in {"explicit_deny", "missing_permission", "exceeds_user_permissions"}


async def test_downstream_sees_both_identities(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    """The GitHub server records ``user -> agent``, not just the user."""
    allow_write("company/backend", seeded.users["imad"].id)
    user_token = await login(client, "imad@example.com")
    agent_token = await delegate(client, user_token, "coding-agent")

    created = await client.post(
        "/mcp/call",
        headers=bearer(agent_token),
        json={
            "tool": "github.create_issue",
            "arguments": {"repo": "company/backend", "title": "Traceable issue"},
        },
    )
    assert created.status_code == 200

    read_back = await client.post(
        "/mcp/call",
        headers=bearer(agent_token),
        json={"tool": "github.get_issue", "arguments": {"number": 1}},
    )
    text = read_back.json()["result"]["content"][0]["text"]
    assert seeded.users["imad"].id in text
    assert seeded.agents["coding-agent"].id in text


async def test_downstream_resource_authorization_still_applies(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    """The gateway says "you may use GitHub"; GitHub says "not this repo"."""
    user_token = await login(client, "imad@example.com")
    agent_token = await delegate(client, user_token, "coding-agent")

    response = await client.post(
        "/mcp/call",
        headers=bearer(agent_token),
        json={
            "tool": "github.create_issue",
            "arguments": {"repo": "company/frontend", "title": "Not my repo"},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "allow"  # the gateway allowed the tool
    assert body["error"]["data"]["reason"] == "resource_forbidden"  # the server denied the repo


async def test_autonomous_agent_runs_as_its_service_account(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    response = await client.post(
        "/mcp/call",
        headers={"X-API-Key": seeded.api_keys["security-agent"]},
        json={
            "tool": "kubernetes.get_logs",
            "arguments": {"namespace": "production", "pod": "api-prod-1"},
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["execution_identity"] == seeded.service_accounts["security"].id
    text = body["result"]["content"][0]["text"]
    assert seeded.service_accounts["security"].id in text
    # No human identity was invented along the way.
    assert seeded.users["imad"].id not in text


async def test_service_account_only_table_is_reachable_through_a_service_account(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    developer = await login(client, "imad@example.com")
    direct = await client.post(
        "/mcp/call",
        headers=bearer(developer),
        json={"tool": "database.query", "arguments": {"table": "private.billing"}},
    )
    assert direct.status_code == 200
    assert direct.json()["error"]["data"]["reason"] == "resource_forbidden"

    via_sa = await client.post(
        "/mcp/call",
        headers={"X-API-Key": seeded.api_keys["reporting-service-account"]},
        json={"tool": "database.query", "arguments": {"table": "private.billing"}},
    )
    assert via_sa.status_code == 200
    assert via_sa.json()["result"]["isError"] is False


async def test_audit_trail_records_the_whole_chain(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    allow_write("company/backend", seeded.users["imad"].id)
    user_token = await login(client, "imad@example.com")
    agent_token = await delegate(client, user_token, "coding-agent")

    await client.post(
        "/mcp/call",
        headers=bearer(agent_token),
        json={
            "tool": "github.create_issue",
            "arguments": {"repo": "company/backend", "title": "Audited"},
            "resource": "company/backend",
        },
    )
    await client.post(
        "/mcp/call",
        headers=bearer(agent_token),
        json={"tool": "kubernetes.delete_namespace", "arguments": {"namespace": "staging"}},
    )

    admin = await login(client, "admin@example.com")
    events = (
        await client.get(
            "/audit/events", headers=bearer(admin), params={"action": "mcp.call", "limit": 50}
        )
    ).json()["events"]

    allowed = [e for e in events if e["tool"] == "github.create_issue"]
    denied = [e for e in events if e["tool"] == "kubernetes.delete_namespace"]

    assert allowed and denied
    assert allowed[0]["user_id"] == seeded.users["imad"].id
    assert allowed[0]["agent_id"] == seeded.agents["coding-agent"].id
    assert allowed[0]["persona"] == "user"
    assert allowed[0]["execution_identity"] == seeded.users["imad"].id
    assert allowed[0]["resource"] == "company/backend"
    assert allowed[0]["decision"] == "allow"

    assert denied[0]["decision"] == "deny"
    assert denied[0]["reason"] in {
        "explicit_deny",
        "missing_permission",
        "exceeds_user_permissions",
    }


async def test_autonomous_audit_has_no_human(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    await client.post(
        "/mcp/call",
        headers={"X-API-Key": seeded.api_keys["security-agent"]},
        json={"tool": "kubernetes.get_logs", "arguments": {"namespace": "production"}},
    )

    admin = await login(client, "admin@example.com")
    events = (
        await client.get(
            "/audit/events",
            headers=bearer(admin),
            params={"tool": "kubernetes.get_logs", "limit": 10},
        )
    ).json()["events"]

    assert events
    event = events[0]
    assert event["user_id"] is None
    assert event["persona"] == "non-user"
    assert event["agent_id"] == seeded.agents["security-agent"].id
    assert event["execution_identity"] == seeded.service_accounts["security"].id


async def test_unknown_tool_is_audited_and_404s(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    token = await login(client, "imad@example.com")
    response = await client.post(
        "/mcp/call", headers=bearer(token), json={"tool": "github.nonexistent", "arguments": {}}
    )
    assert response.status_code == 404
    assert response.json()["error"] == "unknown_tool"

    admin = await login(client, "admin@example.com")
    events = (
        await client.get(
            "/audit/events", headers=bearer(admin), params={"tool": "github.nonexistent"}
        )
    ).json()["events"]
    assert events and events[0]["decision"] == "deny"
