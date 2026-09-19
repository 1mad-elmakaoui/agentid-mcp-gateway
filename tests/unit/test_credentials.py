"""Credential resolution, caching and refresh."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session as DbSession

from agentid.config import Settings
from agentid.context import RequestContext
from agentid.credentials.manager import SERVER_DEFAULT_OWNER, CredentialManager
from agentid.credentials.oauth import make_payload as oauth_payload
from agentid.credentials.refresh import CallableRefreshProvider, RefreshRegistry
from agentid.credentials.vault import SecretMaterial
from agentid.database.seed import SeedResult
from agentid.errors import CredentialError
from agentid.identity.tokens import TokenService
from agentid.models import CredentialType, Persona
from agentid.registry.servers import require_server


@pytest.fixture
def manager(settings: Settings) -> CredentialManager:
    return CredentialManager(settings=settings)


def ctx(**kwargs) -> RequestContext:
    return RequestContext(
        request_id="req_cred", persona=kwargs.pop("persona", Persona.USER), **kwargs
    )


def test_resolve_attaches_a_downstream_token(
    db: DbSession, seeded: SeedResult, manager: CredentialManager, settings: Settings
) -> None:
    server = require_server(db, "github")
    context = ctx(user_id=seeded.users["imad"].id, agent_id=seeded.agents["coding-agent"].id)
    context.tool = "github.create_issue"

    resolved = manager.resolve(db, context, server)
    token = resolved.headers["Authorization"].removeprefix("Bearer ")
    claims = TokenService(settings).verify(token, audience="agentid-mcp:github")

    assert claims.sub == seeded.users["imad"].id
    assert claims.act_sub == seeded.agents["coding-agent"].id
    assert claims.raw["tool"] == "github.create_issue"


def test_resolve_attaches_the_server_credential(
    db: DbSession, seeded: SeedResult, manager: CredentialManager
) -> None:
    server = require_server(db, "github")
    resolved = manager.resolve(db, ctx(user_id=seeded.users["imad"].id), server)
    assert resolved.headers["X-Downstream-Api-Key"] == "downstream-github-secret"
    assert resolved.source == "api_key:gateway"


def test_audit_fields_carry_no_secret(
    db: DbSession, seeded: SeedResult, manager: CredentialManager
) -> None:
    server = require_server(db, "github")
    resolved = manager.resolve(db, ctx(user_id=seeded.users["imad"].id), server)
    fields = resolved.audit_fields()
    assert "downstream-github-secret" not in str(fields)
    assert set(fields) == {"credential_source", "credential_id"}


def test_missing_credential_is_an_explicit_error(
    db: DbSession, seeded: SeedResult, manager: CredentialManager
) -> None:
    server = require_server(db, "github")
    from sqlalchemy import select

    from agentid.models import Credential

    for record in db.scalars(select(Credential).where(Credential.server_id == server.id)):
        db.delete(record)
    db.flush()
    manager.cache.clear()

    with pytest.raises(CredentialError) as exc:
        manager.resolve(db, ctx(user_id=seeded.users["imad"].id), server)
    assert exc.value.code == "credential_not_found"


def test_expired_oauth_credential_is_refreshed(
    db: DbSession, seeded: SeedResult, settings: Settings
) -> None:
    refreshed: list[str] = []

    def refresh(server_name: str, secret: SecretMaterial) -> SecretMaterial:
        refreshed.append(server_name)
        return SecretMaterial(kind="oauth", value="fresh-token", refresh_token="r2")

    registry = RefreshRegistry()
    registry.register("github", CallableRefreshProvider(refresh))
    manager = CredentialManager(settings=settings, refresh_registry=registry)

    server = require_server(db, "github")
    manager.store(
        db,
        server=server,
        credential_type=CredentialType.OAUTH,
        payload=oauth_payload("stale-token", refresh_token="r1", expires_in=-60),
        owner_type=SERVER_DEFAULT_OWNER,
        owner_id=server.id,
    )
    server.credential_type = CredentialType.OAUTH
    db.flush()

    resolved = manager.resolve(db, ctx(user_id=seeded.users["imad"].id), server)
    assert refreshed == ["github"]
    assert resolved.headers["X-Downstream-Authorization"] == "Bearer fresh-token"


def test_expired_credential_without_a_provider_fails_clearly(
    db: DbSession, seeded: SeedResult, settings: Settings
) -> None:
    manager = CredentialManager(settings=settings)
    server = require_server(db, "github")
    manager.store(
        db,
        server=server,
        credential_type=CredentialType.OAUTH,
        payload=oauth_payload("stale-token", expires_in=-60),
        owner_type=SERVER_DEFAULT_OWNER,
        owner_id=server.id,
    )
    server.credential_type = CredentialType.OAUTH
    db.flush()

    with pytest.raises(CredentialError) as exc:
        manager.resolve(db, ctx(user_id=seeded.users["imad"].id), server)
    assert exc.value.code == "credential_expired"


def test_credential_is_encrypted_at_rest(
    db: DbSession, seeded: SeedResult, manager: CredentialManager
) -> None:
    from sqlalchemy import select

    from agentid.models import Credential

    record = db.scalar(select(Credential))
    assert record is not None
    assert "downstream-github-secret" not in record.ciphertext
    assert "downstream" not in record.ciphertext.lower()[:40]
