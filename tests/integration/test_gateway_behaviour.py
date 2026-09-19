"""Cross-cutting gateway behaviour: errors, rate limits, request ids, health."""

from __future__ import annotations

import httpx
import pytest

from agentid.config import Settings
from agentid.database.seed import SeedResult
from agentid.gateway.main import create_app
from tests.conftest import bearer, login


async def test_health_and_root_are_public(client: httpx.AsyncClient) -> None:
    health = await client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    root = await client.get("/")
    assert root.status_code == 200
    assert "endpoints" in root.json()


async def test_every_response_carries_a_request_id(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    response = await client.get("/health")
    assert response.headers["X-Request-Id"].startswith("req_")


async def test_request_id_is_propagated(client: httpx.AsyncClient, seeded: SeedResult) -> None:
    token = await login(client, "imad@example.com")
    response = await client.get(
        "/auth/whoami", headers={**bearer(token), "X-Request-Id": "req_caller_supplied"}
    )
    assert response.headers["X-Request-Id"] == "req_caller_supplied"
    assert response.json()["request_id"] == "req_caller_supplied"


async def test_errors_are_structured(client: httpx.AsyncClient, seeded: SeedResult) -> None:
    token = await login(client, "imad@example.com")
    response = await client.post(
        "/mcp/call", headers=bearer(token), json={"tool": "github.nope", "arguments": {}}
    )
    body = response.json()
    assert response.status_code == 404
    assert body["error"] == "unknown_tool"
    assert body["message"]
    assert body["request_id"]


async def test_downstream_failure_surfaces_as_502(
    client: httpx.AsyncClient, seeded: SeedResult, db
) -> None:
    from agentid.registry.servers import update_server

    update_server(db, "github", endpoint="http://nowhere.invalid")
    db.commit()

    token = await login(client, "imad@example.com")
    response = await client.post(
        "/mcp/call",
        headers=bearer(token),
        json={"tool": "github.search_repository", "arguments": {"query": "x"}},
    )
    assert response.status_code == 502
    assert response.json()["error"] in {"downstream_unreachable", "downstream_timeout"}


async def test_downstream_failure_is_audited(
    client: httpx.AsyncClient, seeded: SeedResult, db, audit_sink
) -> None:
    from agentid.registry.servers import update_server

    update_server(db, "github", endpoint="http://nowhere.invalid")
    db.commit()
    token = await login(client, "imad@example.com")
    audit_sink.clear()

    await client.post(
        "/mcp/call",
        headers=bearer(token),
        json={"tool": "github.search_repository", "arguments": {"query": "x"}},
    )
    errors = [r for r in audit_sink.records if r.decision == "error"]
    assert errors and errors[0].tool == "github.search_repository"


@pytest.mark.parametrize("limit", [3])
async def test_rate_limiting(
    settings: Settings, db_engine, downstream_client, audit_logger, seeded, limit: int
) -> None:
    limited = create_app(
        settings=settings.model_copy(
            update={"rate_limit_enabled": True, "rate_limit_requests": limit}
        ),
        http_client=downstream_client,
        audit=audit_logger,
        create_schema=False,
    )
    transport = httpx.ASGITransport(app=limited)
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway.test") as c:
        token = await login(c, "imad@example.com")
        statuses = [
            (await c.get("/auth/whoami", headers=bearer(token))).status_code
            for _ in range(limit + 2)
        ]
    assert statuses[:limit] == [200] * limit
    assert statuses[-1] == 429


async def test_audit_me_needs_no_admin_rights(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    token = await login(client, "imad@example.com")
    response = await client.get("/audit/me", headers=bearer(token))
    assert response.status_code == 200
    assert all(
        e["user_id"] == seeded.users["imad"].id for e in response.json()["events"]
    )


async def test_audit_events_requires_admin(client: httpx.AsyncClient, seeded: SeedResult) -> None:
    token = await login(client, "imad@example.com")
    assert (await client.get("/audit/events", headers=bearer(token))).status_code == 403
