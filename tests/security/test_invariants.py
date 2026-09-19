"""One test per security invariant (docs/security-model.md §13).

These are requirements, not features: each test names the invariant it pins
down so a regression is unambiguous.
"""

from __future__ import annotations

import httpx
import pytest

from agentid.database.seed import SeedResult
from agentid.identity.tokens import TokenService
from agentid.models import Persona
from agentid.servers.github import allow_write
from tests.conftest import bearer, delegate, login

pytestmark = pytest.mark.security


async def test_invariant_1_every_request_has_an_authenticated_identity(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    for method, path, body in [
        ("get", "/mcp/tools", None),
        ("post", "/mcp/call", {"tool": "github.create_issue", "arguments": {}}),
        ("get", "/audit/events", None),
        ("get", "/registry/servers", None),
        ("get", "/auth/whoami", None),
    ]:
        response = await getattr(client, method)(path, json=body) if body else await getattr(
            client, method
        )(path)
        assert response.status_code == 401, f"{method.upper()} {path} was reachable anonymously"


async def test_invariant_2_personas_stay_distinct(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    human = await client.get(
        "/auth/whoami", headers=bearer(await login(client, "imad@example.com"))
    )
    machine = await client.get(
        "/auth/whoami", headers={"X-API-Key": seeded.api_keys["security-agent"]}
    )
    assert human.json()["persona"] == "user"
    assert machine.json()["persona"] == "non-user"
    assert machine.json()["user_id"] is None


async def test_invariant_3_autonomous_agent_cannot_impersonate_a_human(
    client: httpx.AsyncClient, seeded: SeedResult, settings
) -> None:
    """A forged agent token claiming the user persona must be refused."""
    tokens = TokenService(settings)
    forged, _ = tokens.issue_access_token(
        subject=seeded.agents["security-agent"].id,
        persona=Persona.USER,  # the lie
        subject_type="agent",
    )
    response = await client.get("/auth/whoami", headers=bearer(forged))
    assert response.status_code == 403
    assert response.json()["error"] == "persona_mismatch"


async def test_invariant_3_machine_token_cannot_be_exchanged_for_a_user_token(
    client: httpx.AsyncClient, seeded: SeedResult, settings
) -> None:
    tokens = TokenService(settings)
    agent_token, _ = tokens.issue_access_token(
        subject=seeded.agents["security-agent"].id,
        persona=Persona.NON_USER,
        subject_type="agent",
    )
    response = await client.post(
        "/auth/token",
        json={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": agent_token,
            "actor": "coding-agent",
        },
    )
    assert response.status_code == 403
    assert response.json()["error"] == "persona_violation"


async def test_invariant_4_authentication_does_not_imply_authorization(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    token = await login(client, "imad@example.com")
    # Authentication succeeds...
    assert (await client.get("/auth/whoami", headers=bearer(token))).status_code == 200
    # ...authorization is a separate question, and the answer here is no.
    denied = await client.post(
        "/mcp/call",
        headers=bearer(token),
        json={"tool": "kubernetes.delete_namespace", "arguments": {"namespace": "staging"}},
    )
    assert denied.status_code == 403


async def test_invariant_5_authorization_precedes_routing(
    client: httpx.AsyncClient, seeded: SeedResult, downstream_apps
) -> None:
    """A denied call must never touch the downstream server."""
    calls: list[str] = []
    kubernetes = downstream_apps["kubernetes-mcp.test"]
    original = kubernetes.state.tools["delete_namespace"].handler

    def spy(claims, arguments):  # pragma: no cover - must never run
        calls.append("called")
        return original(claims, arguments)

    kubernetes.state.tools["delete_namespace"].handler = spy

    token = await login(client, "imad@example.com")
    response = await client.post(
        "/mcp/call",
        headers=bearer(token),
        json={"tool": "kubernetes.delete_namespace", "arguments": {"namespace": "staging"}},
    )
    assert response.status_code == 403
    assert calls == [], "the proxy forwarded a request the engine denied"


async def test_invariant_6_service_account_needs_an_explicit_grant(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    token = await login(client, "imad@example.com")
    response = await client.post(
        "/mcp/call",
        headers=bearer(token),
        json={
            "tool": "github.create_issue",
            "arguments": {"repo": "company/backend", "title": "escalation attempt"},
            "service_account": seeded.service_accounts["deployer"].id,
        },
    )
    assert response.status_code == 403
    assert response.json()["error"] == "service_account_not_authorized"


async def test_invariant_7_credentials_never_reach_the_client(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    allow_write("company/backend", seeded.users["imad"].id)
    token = await login(client, "imad@example.com")
    response = await client.post(
        "/mcp/call",
        headers=bearer(token),
        json={
            "tool": "github.create_issue",
            "arguments": {"repo": "company/backend", "title": "no secrets please"},
        },
    )
    assert response.status_code == 200
    assert "downstream-github-secret" not in response.text
    assert "Authorization" not in response.text

    admin = await login(client, "admin@example.com")
    audit = await client.get(
        "/audit/events", headers=bearer(admin), params={"tool": "github.create_issue"}
    )
    assert "downstream-github-secret" not in audit.text
    assert audit.json()["events"][0]["details"]["credential_source"] == "api_key:gateway"


async def test_invariant_8_every_invocation_is_audited(
    client: httpx.AsyncClient, seeded: SeedResult, audit_sink
) -> None:
    allow_write("company/backend", seeded.users["imad"].id)
    token = await login(client, "imad@example.com")
    audit_sink.clear()

    await client.post(
        "/mcp/call",
        headers=bearer(token),
        json={"tool": "github.create_issue", "arguments": {"repo": "company/backend", "title": "a"}},
    )
    await client.post(
        "/mcp/call",
        headers=bearer(token),
        json={"tool": "kubernetes.delete_namespace", "arguments": {"namespace": "staging"}},
    )
    await client.post("/mcp/call", headers=bearer(token), json={"tool": "nope.nope", "arguments": {}})

    calls = [r for r in audit_sink.records if r.action == "mcp.call"]
    assert len(calls) == 3, "allowed, denied and unroutable calls must all be audited"
    assert {r.decision for r in calls} == {"allow", "deny"}


async def test_invariant_9_agent_cannot_exceed_its_delegating_user(
    client: httpx.AsyncClient, seeded: SeedResult, db
) -> None:
    """The admin may read cluster logs directly; the coding agent may not, so
    the admin cannot reach them *through* that agent either."""
    from agentid.identity import service_accounts as sa_svc
    from agentid.models import IdentityType

    sa_svc.grant_service_account(
        db,
        grantee_type=IdentityType.USER,
        grantee_id=seeded.users["admin"].id,
        service_account_id=seeded.service_accounts["security"].id,
    )
    db.commit()

    admin_token = await login(client, "admin@example.com")
    delegated = await delegate(client, admin_token, "coding-agent")

    direct = await client.post(
        "/mcp/call",
        headers=bearer(admin_token),
        json={"tool": "kubernetes.list_pods", "arguments": {"namespace": "default"}},
    )
    assert direct.status_code == 200, direct.text

    through_agent = await client.post(
        "/mcp/call",
        headers=bearer(delegated),
        json={"tool": "kubernetes.list_pods", "arguments": {"namespace": "default"}},
    )
    assert through_agent.status_code == 403
    assert through_agent.json()["error"] in {"explicit_deny", "exceeds_user_permissions"}


async def test_invariant_10_downstream_keeps_resource_authorization(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    token = await login(client, "imad@example.com")
    response = await client.post(
        "/mcp/call",
        headers=bearer(token),
        json={
            "tool": "github.create_issue",
            "arguments": {"repo": "company/docs", "title": "gateway said yes"},
        },
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
    assert response.json()["error"]["data"]["reason"] == "resource_forbidden"
