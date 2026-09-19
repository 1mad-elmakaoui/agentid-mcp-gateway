"""The authorization engine's decision table."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session as DbSession

from agentid.authorization.decisions import Reason
from agentid.authorization.engine import AuthorizationEngine
from agentid.authorization.rbac import upsert_role
from agentid.context import RequestContext
from agentid.database.seed import SeedResult
from agentid.identity import agents as agents_svc
from agentid.identity import service_accounts as sa_svc
from agentid.models import AgentKind, IdentityType, Persona
from agentid.registry.tools import require_tool


@pytest.fixture
def engine(settings) -> AuthorizationEngine:
    return AuthorizationEngine(settings)


def ctx_for(
    *,
    user_id: str | None = None,
    agent_id: str | None = None,
    service_account_id: str | None = None,
    persona: Persona | None = None,
) -> RequestContext:
    if persona is None:
        persona = Persona.USER if user_id else Persona.NON_USER
    return RequestContext(
        request_id="req_test",
        persona=persona,
        user_id=user_id,
        agent_id=agent_id,
        service_account_id=service_account_id,
        scopes=("mcp:tools",),
    )


def test_allows_a_tool_the_chain_permits(db: DbSession, seeded: SeedResult, engine) -> None:
    tool = require_tool(db, "github.create_issue")
    ctx = ctx_for(user_id=seeded.users["imad"].id, agent_id=seeded.agents["coding-agent"].id)
    decision = engine.authorize_tool(db, ctx, tool)
    assert decision.allowed
    assert decision.execution_identity == seeded.users["imad"].id
    assert decision.permission == "github.create_issue"


def test_denies_a_tool_the_role_denies(db: DbSession, seeded: SeedResult, engine) -> None:
    tool = require_tool(db, "kubernetes.delete_namespace")
    ctx = ctx_for(user_id=seeded.users["imad"].id, agent_id=seeded.agents["coding-agent"].id)
    decision = engine.authorize_tool(db, ctx, tool)
    assert not decision.allowed
    assert decision.reason in {Reason.EXPLICIT_DENY, Reason.MISSING_PERMISSION}


def test_agent_cannot_exceed_its_user(db: DbSession, seeded: SeedResult, engine) -> None:
    """Invariant 9: the agent holds database.query, the user does not."""
    upsert_role(db, "narrow-user", allow=["github.read"])
    user = seeded.users["imad"]
    user.roles = [r for r in user.roles if r.name != "developer"]
    from agentid.authorization.rbac import get_role

    user.roles = [get_role(db, "narrow-user")]
    db.flush()

    tool = require_tool(db, "database.query")
    ctx = ctx_for(user_id=user.id, agent_id=seeded.agents["coding-agent"].id)
    decision = engine.authorize_tool(db, ctx, tool)
    assert not decision.allowed
    assert decision.reason == Reason.MISSING_PERMISSION


def test_user_cannot_exceed_its_agent(db: DbSession, seeded: SeedResult, engine) -> None:
    """The intersection cuts both ways: the admin holds kubernetes.get_logs,
    the coding agent does not."""
    tool = require_tool(db, "kubernetes.get_logs")
    ctx = ctx_for(user_id=seeded.users["admin"].id, agent_id=seeded.agents["coding-agent"].id)
    decision = engine.authorize_tool(db, ctx, tool)
    assert not decision.allowed
    assert decision.reason in {Reason.EXPLICIT_DENY, Reason.EXCEEDS_USER_PERMISSIONS}


def test_service_account_requires_an_explicit_grant(
    db: DbSession, seeded: SeedResult, engine
) -> None:
    """Invariant 6: nobody granted imad the security service account."""
    tool = require_tool(db, "kubernetes.get_logs")
    ctx = ctx_for(user_id=seeded.users["imad"].id)
    decision = engine.authorize_tool(
        db, ctx, tool, requested_service_account=seeded.service_accounts["security"].id
    )
    assert not decision.allowed
    assert decision.reason in {
        Reason.MISSING_PERMISSION,
        Reason.SERVICE_ACCOUNT_NOT_AUTHORIZED,
    }


def test_granted_user_may_use_a_service_account(
    db: DbSession, seeded: SeedResult, engine
) -> None:
    tool = require_tool(db, "kubernetes.get_logs")
    ctx = ctx_for(user_id=seeded.users["ops"].id)
    decision = engine.authorize_tool(db, ctx, tool)
    assert decision.allowed, decision.message
    assert decision.service_account_id == seeded.service_accounts["security"].id
    assert decision.execution_identity == seeded.service_accounts["security"].id


def test_revoking_the_grant_denies_immediately(
    db: DbSession, seeded: SeedResult, engine
) -> None:
    sa_svc.revoke_service_account(
        db,
        grantee_type=IdentityType.USER,
        grantee_id=seeded.users["ops"].id,
        service_account_id=seeded.service_accounts["security"].id,
    )
    tool = require_tool(db, "kubernetes.get_logs")
    decision = engine.authorize_tool(db, ctx_for(user_id=seeded.users["ops"].id), tool)
    assert not decision.allowed
    assert decision.reason == Reason.SERVICE_ACCOUNT_NOT_AUTHORIZED


def test_autonomous_agent_executes_through_its_service_account(
    db: DbSession, seeded: SeedResult, engine
) -> None:
    tool = require_tool(db, "kubernetes.get_logs")
    ctx = ctx_for(agent_id=seeded.agents["security-agent"].id)
    decision = engine.authorize_tool(db, ctx, tool)
    assert decision.allowed, decision.message
    assert decision.execution_identity == seeded.service_accounts["security"].id


def test_non_user_persona_carrying_a_user_id_is_rejected(
    db: DbSession, seeded: SeedResult, engine
) -> None:
    """Invariant 3: an autonomous caller cannot wear a human's identity."""
    tool = require_tool(db, "github.create_issue")
    ctx = ctx_for(
        user_id=seeded.users["imad"].id,
        agent_id=seeded.agents["coding-agent"].id,
        persona=Persona.NON_USER,
    )
    decision = engine.authorize_tool(db, ctx, tool)
    assert not decision.allowed
    assert decision.reason == Reason.PERSONA_VIOLATION


def test_autonomous_agent_cannot_act_as_a_user(db: DbSession, seeded: SeedResult, engine) -> None:
    agents_svc.grant_agent_to_user(
        db, user_id=seeded.users["imad"].id, agent_id=seeded.agents["security-agent"].id
    )
    tool = require_tool(db, "kubernetes.get_logs")
    ctx = ctx_for(user_id=seeded.users["imad"].id, agent_id=seeded.agents["security-agent"].id)
    decision = engine.authorize_tool(db, ctx, tool)
    assert not decision.allowed
    assert decision.reason == Reason.PERSONA_VIOLATION


def test_unauthenticated_context_is_denied(db: DbSession, seeded: SeedResult, engine) -> None:
    """Invariant 1."""
    tool = require_tool(db, "github.create_issue")
    ctx = RequestContext(request_id="req_anon", persona=Persona.USER)
    decision = engine.authorize_tool(db, ctx, tool)
    assert not decision.allowed
    assert decision.reason == Reason.UNAUTHENTICATED


def test_missing_scope_is_denied(db: DbSession, seeded: SeedResult, engine) -> None:
    tool = require_tool(db, "github.create_issue")
    ctx = ctx_for(user_id=seeded.users["imad"].id)
    ctx.scopes = ("profile",)
    decision = engine.authorize_tool(db, ctx, tool)
    assert not decision.allowed
    assert decision.reason == Reason.MISSING_SCOPE


def test_disabled_identity_is_denied(db: DbSession, seeded: SeedResult, engine) -> None:
    seeded.agents["coding-agent"].is_active = False
    db.flush()
    tool = require_tool(db, "github.create_issue")
    ctx = ctx_for(user_id=seeded.users["imad"].id, agent_id=seeded.agents["coding-agent"].id)
    decision = engine.authorize_tool(db, ctx, tool)
    assert not decision.allowed
    assert decision.reason == Reason.IDENTITY_DISABLED


def test_disabled_server_is_denied(db: DbSession, seeded: SeedResult, engine) -> None:
    seeded.servers["github"].enabled = False
    db.flush()
    tool = require_tool(db, "github.create_issue")
    ctx = ctx_for(user_id=seeded.users["imad"].id)
    decision = engine.authorize_tool(db, ctx, tool)
    assert not decision.allowed
    assert decision.reason == Reason.SERVER_DISABLED


def test_service_account_caller_is_its_own_principal(
    db: DbSession, seeded: SeedResult, engine
) -> None:
    tool = require_tool(db, "database.query")
    ctx = ctx_for(service_account_id=seeded.service_accounts["reporting"].id)
    decision = engine.authorize_tool(db, ctx, tool)
    assert decision.allowed, decision.message
    assert decision.execution_identity == seeded.service_accounts["reporting"].id


def test_service_account_still_needs_the_permission(
    db: DbSession, seeded: SeedResult, engine
) -> None:
    tool = require_tool(db, "github.create_issue")
    ctx = ctx_for(service_account_id=seeded.service_accounts["reporting"].id)
    decision = engine.authorize_tool(db, ctx, tool)
    assert not decision.allowed
    assert decision.reason == Reason.SERVICE_ACCOUNT_NOT_PERMITTED


def test_borrowed_service_account_must_hold_the_permission(
    db: DbSession, seeded: SeedResult, engine
) -> None:
    """A grant lets you borrow an identity; it does not widen that identity."""
    sa = sa_svc.create_service_account(db, name="empty-sa", description="no roles")
    sa_svc.grant_service_account(
        db,
        grantee_type=IdentityType.USER,
        grantee_id=seeded.users["ops"].id,
        service_account_id=sa.id,
    )
    tool = require_tool(db, "kubernetes.get_logs")
    ctx = ctx_for(user_id=seeded.users["ops"].id)
    decision = engine.authorize_tool(db, ctx, tool, requested_service_account=sa.id)
    assert not decision.allowed
    assert decision.reason == Reason.SERVICE_ACCOUNT_NOT_PERMITTED


def test_autonomous_agent_without_a_grant_is_denied(
    db: DbSession, seeded: SeedResult, engine
) -> None:
    lonely = agents_svc.create_agent(
        db,
        name="lonely-agent",
        kind=AgentKind.AUTONOMOUS,
        description="no service account grant",
        roles=["security-agent"],
    )
    tool = require_tool(db, "kubernetes.get_logs")
    decision = engine.authorize_tool(db, ctx_for(agent_id=lonely.id), tool)
    assert not decision.allowed
    assert decision.reason == Reason.SERVICE_ACCOUNT_NOT_AUTHORIZED
