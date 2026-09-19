"""The downstream SDK verifier — what an MCP server will and will not accept."""

from __future__ import annotations

import pytest

from agentid.config import Settings
from agentid.identity.tokens import TokenService
from agentid.models import Persona
from agentid.sdk.server import TokenVerifier, VerificationError


@pytest.fixture
def tokens(settings: Settings) -> TokenService:
    return TokenService(settings)


@pytest.fixture
def verifier(settings: Settings) -> TokenVerifier:
    return TokenVerifier(
        secret=settings.secret_key, audience="agentid-mcp:github", issuer=settings.jwt_issuer
    )


def test_accepts_a_token_minted_for_this_server(
    tokens: TokenService, verifier: TokenVerifier
) -> None:
    raw = tokens.issue_downstream_token(
        server_name="github", user_id="user_1", agent_id="agent_1"
    )
    claims = verifier.verify(raw)
    assert claims.subject == "user_1"
    assert claims.agent == "agent_1"
    assert claims.identity_chain() == "user_1 -> agent_1"


def test_rejects_a_token_minted_for_another_server(
    tokens: TokenService, verifier: TokenVerifier
) -> None:
    raw = tokens.issue_downstream_token(server_name="kubernetes", user_id="user_1")
    with pytest.raises(VerificationError) as exc:
        verifier.verify(raw)
    assert exc.value.code == "invalid_audience"


def test_rejects_a_client_gateway_token(tokens: TokenService, verifier: TokenVerifier) -> None:
    """A caller cannot replay their own gateway token against a server."""
    raw, _ = tokens.issue_access_token(
        subject="user_1", persona=Persona.USER, subject_type="user"
    )
    with pytest.raises(VerificationError) as exc:
        verifier.verify(raw)
    assert exc.value.code == "invalid_audience"


def test_rejects_a_token_from_another_issuer(settings: Settings) -> None:
    other = TokenService(Settings(secret_key=settings.secret_key, jwt_issuer="someone-else"))
    raw = other.issue_downstream_token(server_name="github", user_id="user_1")
    verifier = TokenVerifier(secret=settings.secret_key, audience="agentid-mcp:github")
    with pytest.raises(VerificationError) as exc:
        verifier.verify(raw)
    assert exc.value.code == "invalid_issuer"


def test_rejects_a_token_signed_with_another_key(tokens: TokenService) -> None:
    raw = tokens.issue_downstream_token(server_name="github", user_id="user_1")
    verifier = TokenVerifier(secret="a-different-signing-key", audience="agentid-mcp:github")
    with pytest.raises(VerificationError):
        verifier.verify(raw)


def test_rejects_an_expired_token(settings: Settings, verifier: TokenVerifier) -> None:
    import time

    tokens = TokenService(settings)
    raw = tokens.issue_downstream_token(
        server_name="github", user_id="user_1", ttl_seconds=1
    )
    time.sleep(1.1 + verifier.leeway_seconds)
    with pytest.raises(VerificationError) as exc:
        verifier.verify(raw)
    assert exc.value.code == "token_expired"


@pytest.mark.parametrize(
    ("header", "code"),
    [(None, "missing_credential"), ("", "missing_credential"), ("Basic abc", "malformed_credential")],
)
def test_header_parsing(verifier: TokenVerifier, header: str | None, code: str) -> None:
    with pytest.raises(VerificationError) as exc:
        verifier.verify_header(header)
    assert exc.value.code == code


def test_claims_expose_the_full_chain(tokens: TokenService, verifier: TokenVerifier) -> None:
    raw = tokens.issue_downstream_token(
        server_name="github",
        user_id="user_1",
        agent_id="agent_1",
        service_account_id="sa_1",
        tool="github.create_issue",
    )
    claims = verifier.verify(raw)
    assert claims.subject == "sa_1"
    assert claims.human_user == "user_1"
    assert claims.identity_chain() == "user_1 -> agent_1 -> sa_1"
    assert claims.to_dict()["tool"] == "github.create_issue"


def test_autonomous_claims_have_no_human(tokens: TokenService, verifier: TokenVerifier) -> None:
    raw = tokens.issue_downstream_token(
        server_name="github",
        agent_id="security-agent",
        service_account_id="sa_security",
        persona=Persona.NON_USER,
    )
    claims = verifier.verify(raw)
    assert claims.is_autonomous
    assert claims.human_user is None
    assert claims.identity_chain() == "security-agent -> sa_security"
