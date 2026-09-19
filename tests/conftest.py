"""Shared test fixtures.

The whole suite runs in-process: the gateway talks to the example MCP servers
over an ASGI transport, so the full authenticate -> authorize -> credential ->
route -> audit path is exercised without a network or a database server.
"""

from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest
from sqlalchemy.orm import Session as DbSession

from agentid.audit.logger import AuditLogger
from agentid.audit.storage import DatabaseSink, MemorySink
from agentid.config import Settings
from agentid.database import engine as db_engine_module
from agentid.database.seed import DEMO_PASSWORD, SeedResult, seed
from agentid.gateway.main import create_app
from agentid.servers.github import create_app as create_github_app
from agentid.servers.github import reset_state as reset_github_state
from agentid.servers.kubernetes import create_app as create_kubernetes_app
from agentid.servers.postgres import create_app as create_postgres_app

TEST_SECRET = "test-secret-key-not-for-production"

DOWNSTREAM_ENDPOINTS = {
    "github": "http://github-mcp.test",
    "database": "http://postgres-mcp.test",
    "kubernetes": "http://kubernetes-mcp.test",
}


class MultiAppTransport(httpx.AsyncBaseTransport):
    """Dispatches outbound requests to in-process ASGI apps by host."""

    def __init__(self, apps: dict[str, object]) -> None:
        self._transports = {
            host: httpx.ASGITransport(app=app) for host, app in apps.items()
        }

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        transport = self._transports.get(request.url.host)
        if transport is None:  # pragma: no cover - misconfigured test
            raise httpx.ConnectError(f"no test app registered for {request.url.host}")
        return await transport.handle_async_request(request)


@pytest.fixture
def settings() -> Settings:
    return Settings(
        environment="test",
        database_url="sqlite:///:memory:",
        secret_key=TEST_SECRET,
        audit_stdout=False,
        rate_limit_enabled=False,
        access_token_ttl_seconds=3600,
        delegated_token_ttl_seconds=900,
        downstream_token_ttl_seconds=120,
    )


@pytest.fixture
def db_engine(settings: Settings):
    engine = db_engine_module.create_db_engine(settings.database_url, settings=settings)
    db_engine_module.configure(engine)
    db_engine_module.create_all(engine)
    yield engine
    db_engine_module.drop_all(engine)
    db_engine_module.reset()
    engine.dispose()


@pytest.fixture
def db(db_engine) -> Iterator[DbSession]:
    session = db_engine_module.get_session_factory()()
    try:
        yield session
        session.commit()
    finally:
        session.close()


@pytest.fixture
def downstream_apps(settings: Settings) -> dict[str, object]:
    reset_github_state()
    return {
        "github-mcp.test": create_github_app(secret=settings.secret_key),
        "postgres-mcp.test": create_postgres_app(secret=settings.secret_key),
        "kubernetes-mcp.test": create_kubernetes_app(secret=settings.secret_key),
    }


@pytest.fixture
def downstream_client(downstream_apps) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=MultiAppTransport(downstream_apps))


@pytest.fixture
def audit_sink() -> MemorySink:
    return MemorySink()


@pytest.fixture
def audit_logger(settings: Settings, audit_sink: MemorySink) -> AuditLogger:
    return AuditLogger(settings=settings, sinks=[DatabaseSink(), audit_sink])


@pytest.fixture
def seeded(db: DbSession, settings: Settings) -> SeedResult:
    from agentid.credentials.manager import CredentialManager

    result = seed(
        db,
        endpoints=DOWNSTREAM_ENDPOINTS,
        credentials=CredentialManager(settings=settings),
    )
    return result


@pytest.fixture
def app(settings: Settings, db_engine, downstream_client, audit_logger):
    return create_app(
        settings=settings,
        http_client=downstream_client,
        audit=audit_logger,
        create_schema=False,
    )


@pytest.fixture
async def client(app) -> Iterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway.test") as c:
        yield c


@pytest.fixture
def demo_password() -> str:
    return DEMO_PASSWORD


# -- helpers -------------------------------------------------------------


async def login(client: httpx.AsyncClient, email: str, password: str = DEMO_PASSWORD) -> str:
    response = await client.post("/auth/login", json={"email": email, "password": password})
    response.raise_for_status()
    return response.json()["access_token"]


async def delegate(client: httpx.AsyncClient, user_token: str, agent: str) -> str:
    response = await client.post(
        "/auth/token",
        json={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": user_token,
            "actor": agent,
        },
    )
    response.raise_for_status()
    return response.json()["access_token"]


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def helpers():
    class Helpers:
        login = staticmethod(login)
        delegate = staticmethod(delegate)
        bearer = staticmethod(bearer)

    return Helpers
