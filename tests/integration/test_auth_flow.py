"""Authentication, delegation and identity endpoints over HTTP."""

from __future__ import annotations

import httpx
import pytest

from agentid.database.seed import DEMO_PASSWORD, SeedResult
from tests.conftest import bearer, delegate, login


async def test_login_returns_a_user_token(client: httpx.AsyncClient, seeded: SeedResult) -> None:
    response = await client.post(
        "/auth/login", json={"email": "imad@example.com", "password": DEMO_PASSWORD}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "Bearer"
    assert body["session_id"]
    assert body["expires_in"] > 0


async def test_login_with_a_bad_password_is_rejected(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    response = await client.post(
        "/auth/login", json={"email": "imad@example.com", "password": "wrong"}
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_credentials"


async def test_unknown_user_and_bad_password_are_indistinguishable(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    unknown = await client.post(
        "/auth/login", json={"email": "nobody@example.com", "password": "x"}
    )
    bad = await client.post(
        "/auth/login", json={"email": "imad@example.com", "password": "x"}
    )
    def body(response: httpx.Response) -> dict:
        payload = response.json()
        payload.pop("request_id", None)
        return payload

    assert body(unknown) == body(bad)


async def test_whoami_describes_the_caller(client: httpx.AsyncClient, seeded: SeedResult) -> None:
    token = await login(client, "imad@example.com")
    response = await client.get("/auth/whoami", headers=bearer(token))
    body = response.json()
    assert body["persona"] == "user"
    assert body["user_id"] == seeded.users["imad"].id
    assert body["delegated"] is False
    assert "github.create_issue" in body["permissions"]


async def test_requests_without_a_credential_are_rejected(client: httpx.AsyncClient) -> None:
    response = await client.get("/auth/whoami")
    assert response.status_code == 401
    assert response.json()["error"] == "missing_credential"
    assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_delegation_preserves_both_identities(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    user_token = await login(client, "imad@example.com")
    agent_token = await delegate(client, user_token, "coding-agent")

    response = await client.get("/auth/whoami", headers=bearer(agent_token))
    body = response.json()
    assert body["user_id"] == seeded.users["imad"].id
    assert body["agent_id"] == seeded.agents["coding-agent"].id
    assert body["delegated"] is True
    assert body["persona"] == "user"


async def test_delegation_requires_an_explicit_grant(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    """ops@example.com never authorized the coding agent."""
    user_token = await login(client, "ops@example.com")
    response = await client.post(
        "/auth/token",
        json={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": user_token,
            "actor": "coding-agent",
        },
    )
    assert response.status_code == 403
    assert response.json()["error"] == "delegation_not_granted"


async def test_delegation_to_an_autonomous_agent_is_refused(
    client: httpx.AsyncClient, seeded: SeedResult, db
) -> None:
    from agentid.identity import agents as agents_svc

    agents_svc.grant_agent_to_user(
        db, user_id=seeded.users["imad"].id, agent_id=seeded.agents["security-agent"].id
    )
    db.commit()

    user_token = await login(client, "imad@example.com")
    response = await client.post(
        "/auth/token",
        json={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": user_token,
            "actor": "security-agent",
        },
    )
    assert response.status_code == 403
    assert response.json()["error"] == "autonomous_agent_delegation"


async def test_unsupported_grant_type_is_rejected(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    user_token = await login(client, "imad@example.com")
    response = await client.post(
        "/auth/token",
        json={
            "grant_type": "password",
            "subject_token": user_token,
            "actor": "coding-agent",
        },
    )
    assert response.status_code == 422
    assert response.json()["error"] == "unsupported_grant_type"


async def test_logout_revokes_the_session(client: httpx.AsyncClient, seeded: SeedResult) -> None:
    token = await login(client, "imad@example.com")
    assert (await client.post("/auth/logout", headers=bearer(token))).status_code == 200

    after = await client.get("/auth/whoami", headers=bearer(token))
    assert after.status_code == 401
    assert after.json()["error"] == "session_inactive"


async def test_revoking_the_session_kills_delegated_tokens(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    user_token = await login(client, "imad@example.com")
    agent_token = await delegate(client, user_token, "coding-agent")
    await client.post("/auth/logout", headers=bearer(user_token))

    response = await client.get("/auth/whoami", headers=bearer(agent_token))
    assert response.status_code == 401


async def test_introspect_only_shows_your_own_token(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    imad_token = await login(client, "imad@example.com")
    ops_token = await login(client, "ops@example.com")

    own = await client.post(
        "/auth/introspect", json={"token": imad_token}, headers=bearer(imad_token)
    )
    assert own.json()["active"] is True

    other = await client.post(
        "/auth/introspect", json={"token": ops_token}, headers=bearer(imad_token)
    )
    assert other.json() == {"active": False}


async def test_api_key_authenticates_an_agent(
    client: httpx.AsyncClient, seeded: SeedResult
) -> None:
    response = await client.get(
        "/auth/whoami", headers={"X-API-Key": seeded.api_keys["security-agent"]}
    )
    body = response.json()
    assert body["persona"] == "non-user"
    assert body["agent_id"] == seeded.agents["security-agent"].id
    assert body["user_id"] is None


async def test_revoked_api_key_stops_working(
    client: httpx.AsyncClient, seeded: SeedResult, db
) -> None:
    from agentid.identity import api_keys as api_keys_svc

    keys = api_keys_svc.list_api_keys(db, owner_id=seeded.agents["security-agent"].id)
    api_keys_svc.revoke_api_key(db, keys[0].id)
    db.commit()

    response = await client.get(
        "/auth/whoami", headers={"X-API-Key": seeded.api_keys["security-agent"]}
    )
    assert response.status_code == 401
    assert response.json()["error"] == "api_key_inactive"


@pytest.mark.parametrize("value", ["garbage", "Bearer", "Basic abc", "Bearer not.a.jwt"])
async def test_malformed_credentials_are_rejected(
    client: httpx.AsyncClient, seeded: SeedResult, value: str
) -> None:
    response = await client.get("/auth/whoami", headers={"Authorization": value})
    assert response.status_code == 401
