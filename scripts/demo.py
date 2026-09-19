#!/usr/bin/env python3
"""The AgentID security demo.

Runs the whole gateway in-process — no containers, no network — and walks the
three scenarios from the architecture document:

1. ALLOWED    Imad -> coding-agent -> github.create_issue
2. DENIED     Imad -> coding-agent -> kubernetes.delete_namespace
3. DELEGATION the audit trail shows user *and* agent, not just the user

It finishes with the autonomous case, where no human identity exists at all.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentid.audit.logger import AuditLogger  # noqa: E402
from agentid.audit.storage import DatabaseSink  # noqa: E402
from agentid.config import Settings  # noqa: E402
from agentid.credentials.manager import CredentialManager  # noqa: E402
from agentid.database import engine as db_engine  # noqa: E402
from agentid.database.seed import DEMO_PASSWORD, seed  # noqa: E402
from agentid.gateway.main import create_app  # noqa: E402
from agentid.servers.github import allow_write  # noqa: E402
from agentid.servers.github import create_app as create_github
from agentid.servers.github import reset_state as reset_github  # noqa: E402
from agentid.servers.kubernetes import create_app as create_kubernetes  # noqa: E402
from agentid.servers.postgres import create_app as create_postgres  # noqa: E402

ENDPOINTS = {
    "github": "http://github-mcp.demo",
    "database": "http://postgres-mcp.demo",
    "kubernetes": "http://kubernetes-mcp.demo",
}

BOX = 62


class _MultiAppTransport(httpx.AsyncBaseTransport):
    def __init__(self, apps: dict[str, Any]) -> None:
        self._transports = {host: httpx.ASGITransport(app=app) for host, app in apps.items()}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        transport = self._transports[request.url.host]
        return await transport.handle_async_request(request)


def _rule(char: str = "─") -> str:
    return char * BOX


def _header(title: str) -> str:
    return f"\n{_rule('━')}\n  {title}\n{_rule('━')}"


def _chain(*steps: tuple[str, str]) -> str:
    lines = []
    for index, (label, value) in enumerate(steps):
        lines.append(f"  {label:<14} {value}")
        if index < len(steps) - 1:
            lines.append(f"  {'':<14}   │")
            lines.append(f"  {'':<14}   ▼")
    return "\n".join(lines)


async def _run(json_output: bool) -> int:
    settings = Settings(
        environment="demo",
        database_url="sqlite:///:memory:",
        secret_key="demo-secret-key-not-for-production",
        audit_stdout=False,
        rate_limit_enabled=False,
    )
    engine = db_engine.create_db_engine(settings.database_url, settings=settings)
    db_engine.configure(engine)
    db_engine.create_all(engine)

    reset_github()
    downstream = _MultiAppTransport(
        {
            "github-mcp.demo": create_github(secret=settings.secret_key),
            "postgres-mcp.demo": create_postgres(secret=settings.secret_key),
            "kubernetes-mcp.demo": create_kubernetes(secret=settings.secret_key),
        }
    )

    with db_engine.session_scope() as db:
        seeded = seed(
            db, endpoints=ENDPOINTS, credentials=CredentialManager(settings=settings)
        )
        imad_id = seeded.users["imad"].id
        agent_id = seeded.agents["coding-agent"].id
        security_agent_id = seeded.agents["security-agent"].id
        security_sa_id = seeded.service_accounts["security"].id
        deployer_id = seeded.service_accounts["deployer"].id
        security_key = seeded.api_keys["security-agent"]

    allow_write("company/backend", imad_id)

    app = create_app(
        settings=settings,
        http_client=httpx.AsyncClient(transport=downstream),
        audit=AuditLogger(settings=settings, sinks=[DatabaseSink()]),
        create_schema=False,
    )

    results: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://agentid.demo"
    ) as client:
        login = await client.post(
            "/auth/login", json={"email": "imad@example.com", "password": DEMO_PASSWORD}
        )
        user_token = login.json()["access_token"]

        exchange = await client.post(
            "/auth/token",
            json={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": user_token,
                "actor": "coding-agent",
            },
        )
        agent_token = exchange.json()["access_token"]
        auth = {"Authorization": f"Bearer {agent_token}"}

        if not json_output:
            print(_header("AGENTID SECURITY DEMO"))
            print(f"  user            imad@example.com ({imad_id})")
            print(f"  agent           coding-agent ({agent_id})")
            print("  delegated token sub = user, act.sub = agent")

        # 1 -- allowed ----------------------------------------------------
        discovery = await client.post(
            "/mcp/tools/search",
            headers=auth,
            json={"query": "create a github issue", "limit": 3, "include_schema": False},
        )
        allowed = await client.post(
            "/mcp/call",
            headers=auth,
            json={
                "tool": "github.create_issue",
                "arguments": {"repo": "company/backend", "title": "Flaky test in CI"},
                "resource": "company/backend",
            },
        )
        results.append(
            {"scenario": "allowed", "status": allowed.status_code, "body": allowed.json()}
        )

        if not json_output:
            print(_header("1. ALLOWED"))
            print("  tool search (only what this chain may invoke):")
            for match in discovery.json()["tools"]:
                print(f"    • {match['name']}")
            print(f"  filtered out: {discovery.json()['filtered_out']} tool(s)\n")
            print(
                _chain(
                    ("USER", "imad@example.com"),
                    ("AGENT", "coding-agent"),
                    ("TOOL", "github.create_issue"),
                    ("POLICY", "developer ∩ coding-agent"),
                    ("DECISION", "✓ ALLOWED"),
                    ("GITHUB MCP", allowed.json()["result"]["content"][0]["text"]),
                )
            )

        # 2 -- denied -----------------------------------------------------
        denied = await client.post(
            "/mcp/call",
            headers=auth,
            json={"tool": "kubernetes.delete_namespace", "arguments": {"namespace": "staging"}},
        )
        results.append({"scenario": "denied", "status": denied.status_code, "body": denied.json()})

        if not json_output:
            print(_header("2. DENIED"))
            print(
                _chain(
                    ("USER", "imad@example.com"),
                    ("AGENT", "coding-agent"),
                    ("TOOL", "kubernetes.delete_namespace"),
                    ("POLICY", "developer"),
                    ("DECISION", "✗ DENIED"),
                    ("RESPONSE", f"{denied.status_code} {denied.json()['error']}"),
                )
            )
            print("\n  The request never reached the Kubernetes MCP server.")

        # 3 -- escalation attempt ----------------------------------------
        escalation = await client.post(
            "/mcp/call",
            headers=auth,
            json={
                "tool": "github.create_issue",
                "arguments": {"repo": "company/backend", "title": "via production-deployer"},
                "service_account": deployer_id,
            },
        )
        results.append(
            {
                "scenario": "service_account",
                "status": escalation.status_code,
                "body": escalation.json(),
            }
        )

        if not json_output:
            print(_header("3. UNAUTHORIZED SERVICE ACCOUNT"))
            print(
                _chain(
                    ("USER", "imad@example.com"),
                    ("AGENT", "coding-agent"),
                    ("SERVICE ACCT", "production-deployer"),
                    ("DECISION", "✗ DENIED"),
                    ("RESPONSE", f"{escalation.status_code} {escalation.json()['error']}"),
                )
            )
            print("\n  The credential was never resolved, so it could never leak.")

        # 4 -- autonomous -------------------------------------------------
        autonomous = await client.post(
            "/mcp/call",
            headers={"X-API-Key": security_key},
            json={
                "tool": "kubernetes.get_logs",
                "arguments": {"namespace": "production", "pod": "api-prod-1"},
            },
        )
        results.append(
            {"scenario": "autonomous", "status": autonomous.status_code, "body": autonomous.json()}
        )

        if not json_output:
            print(_header("4. AUTONOMOUS AGENT (no human in the chain)"))
            print(
                _chain(
                    ("SCHEDULE", "02:00"),
                    ("AGENT", f"security-agent ({security_agent_id})"),
                    ("IDENTITY", "persona = non-user, user = null"),
                    ("EXECUTES AS", f"security-service-account ({security_sa_id})"),
                    ("DECISION", "✓ ALLOWED"),
                    ("K8S MCP", autonomous.json()["result"]["content"][0]["text"]),
                )
            )

        # 5 -- audit ------------------------------------------------------
        admin_login = await client.post(
            "/auth/login", json={"email": "admin@example.com", "password": DEMO_PASSWORD}
        )
        admin_auth = {"Authorization": f"Bearer {admin_login.json()['access_token']}"}
        events = (
            await client.get(
                "/audit/events",
                headers=admin_auth,
                params={"action": "mcp.call", "limit": 20},
            )
        ).json()["events"]
        results.append({"scenario": "audit", "events": events})

        if not json_output:
            print(_header("5. AUDIT TRAIL"))
            print(f"  {'TOOL':<32}{'DECISION':<9}{'USER':<22}{'AGENT':<22}EXECUTED AS")
            print(f"  {_rule()}")
            for event in reversed(events):
                print(
                    f"  {str(event['tool'])[:31]:<32}"
                    f"{event['decision']:<9}"
                    f"{str(event['user_id'] or '—')[:21]:<22}"
                    f"{str(event['agent_id'] or '—')[:21]:<22}"
                    f"{event['execution_identity']}"
                )
            print(
                "\n  Both identities survive: the audit answers who authorized the\n"
                "  operation and who performed it — not just one of the two."
            )
            print(_header("DONE"))

    if json_output:
        print(json.dumps(results, indent=2, default=str))

    ok = (
        results[0]["status"] == 200
        and results[1]["status"] == 403
        and results[2]["status"] == 403
        and results[3]["status"] == 200
        and len(results[4]["events"]) >= 4
    )
    db_engine.reset()
    engine.dispose()
    return 0 if ok else 1


def run_demo(*, json_output: bool = False) -> int:
    return asyncio.run(_run(json_output))


if __name__ == "__main__":
    raise SystemExit(run_demo(json_output="--json" in sys.argv))
