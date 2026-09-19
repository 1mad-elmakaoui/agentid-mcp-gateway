"""Audit record construction and redaction."""

from __future__ import annotations

from agentid.audit.events import REDACTED, Action, AuditRecord, Outcome, redact
from agentid.context import RequestContext
from agentid.models import Persona


def test_redacts_known_secret_keys() -> None:
    payload = {
        "authorization": "Bearer abc",
        "api_key": "ghp_secret",
        "nested": {"access_token": "tok", "safe": "value"},
        "list": [{"password": "hunter2"}],
    }
    cleaned = redact(payload)
    assert cleaned["authorization"] == REDACTED
    assert cleaned["api_key"] == REDACTED
    assert cleaned["nested"]["access_token"] == REDACTED
    assert cleaned["nested"]["safe"] == "value"
    assert cleaned["list"][0]["password"] == REDACTED


def test_redaction_is_case_insensitive() -> None:
    assert redact({"API_KEY": "x"})["API_KEY"] == REDACTED
    assert redact({"X-Downstream-Api-Key": "x"})["X-Downstream-Api-Key"] == REDACTED


def test_record_from_context_keeps_the_whole_chain() -> None:
    ctx = RequestContext(
        request_id="req_1",
        persona=Persona.USER,
        user_id="user_1",
        agent_id="agent_1",
        service_account_id="sa_1",
        session_id="sess_1",
    )
    ctx.with_tool(server="github", tool="github.create_issue", resource="company/backend")
    record = AuditRecord.from_context(
        ctx, action=Action.TOOL_CALL, decision=Outcome.ALLOW, reason="allowed"
    )

    assert record.user_id == "user_1"
    assert record.agent_id == "agent_1"
    assert record.service_account_id == "sa_1"
    assert record.execution_identity == "sa_1"
    assert record.persona == Persona.USER
    assert record.tool == "github.create_issue"
    assert record.resource == "company/backend"


def test_record_redacts_details_on_construction() -> None:
    ctx = RequestContext(request_id="req_1", persona=Persona.USER, user_id="user_1")
    record = AuditRecord.from_context(
        ctx,
        action=Action.TOOL_CALL,
        decision=Outcome.ALLOW,
        details={"headers": {"authorization": "Bearer leak"}},
    )
    assert record.details["headers"]["authorization"] == REDACTED
    assert "leak" not in str(record.to_dict())


def test_autonomous_record_has_no_user() -> None:
    ctx = RequestContext(
        request_id="req_2",
        persona=Persona.NON_USER,
        agent_id="security-agent",
        service_account_id="sa_security",
    )
    record = AuditRecord.from_context(ctx, action=Action.TOOL_CALL, decision=Outcome.ALLOW)
    payload = record.to_dict()
    assert payload["user_id"] is None
    assert payload["persona"] == "non-user"
    assert payload["execution_identity"] == "sa_security"
