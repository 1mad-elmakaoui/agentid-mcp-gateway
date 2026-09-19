"""Token issuing and verification."""

from __future__ import annotations

import time

import jwt
import pytest

from agentid.config import Settings
from agentid.errors import AuthenticationError
from agentid.identity.tokens import TokenService, TokenType
from agentid.models import Persona


@pytest.fixture
def tokens(settings: Settings) -> TokenService:
    return TokenService(settings)


def test_access_token_round_trip(tokens: TokenService) -> None:
    token, claims = tokens.issue_access_token(
        subject="user_1", persona=Persona.USER, subject_type="user"
    )
    verified = tokens.verify(token)
    assert verified.sub == "user_1"
    assert verified.persona == Persona.USER
    assert verified.token_type == TokenType.ACCESS
    assert verified.jti == claims.jti
    assert not verified.is_delegated


def test_delegated_token_carries_sub_and_act(tokens: TokenService) -> None:
    token, _ = tokens.issue_delegated_token(user_id="user_123", agent_id="agent_coding")
    claims = tokens.verify(token)
    assert claims.sub == "user_123"
    assert claims.act_sub == "agent_coding"
    assert claims.is_delegated
    assert claims.persona == Persona.USER
    assert claims.raw["act"] == {"sub": "agent_coding", "sub_type": "agent"}


def test_downstream_token_has_its_own_audience(tokens: TokenService, settings: Settings) -> None:
    raw = tokens.issue_downstream_token(
        server_name="github", user_id="user_1", agent_id="agent_1"
    )
    # It does not verify against the gateway audience...
    with pytest.raises(AuthenticationError) as exc:
        tokens.verify(raw)
    assert exc.value.code == "invalid_audience"
    # ...only against the server's own.
    claims = tokens.verify(raw, audience="agentid-mcp:github")
    assert claims.token_type == TokenType.DOWNSTREAM
    assert claims.raw["on_behalf_of"] == "user_1"


def test_downstream_subject_is_the_execution_identity(tokens: TokenService) -> None:
    raw = tokens.issue_downstream_token(
        server_name="kubernetes",
        user_id="user_1",
        agent_id="agent_1",
        service_account_id="sa_prod",
    )
    claims = tokens.verify(raw, audience="agentid-mcp:kubernetes")
    assert claims.sub == "sa_prod"
    assert claims.raw["on_behalf_of"] == "user_1"
    assert claims.act_sub == "agent_1"


def test_expired_token_is_rejected(tokens: TokenService) -> None:
    token, _ = tokens.issue_access_token(
        subject="user_1", persona=Persona.USER, subject_type="user", ttl_seconds=1
    )
    payload = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
    assert payload["exp"] - payload["iat"] == 1
    time.sleep(1.1)
    with pytest.raises(AuthenticationError) as exc:
        tokens.verify(token)
    assert exc.value.code == "token_expired"


def test_token_signed_with_another_key_is_rejected(tokens: TokenService, settings: Settings) -> None:
    forged = jwt.encode(
        {
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "sub": "user_1",
            "persona": "user",
            "typ": "access",
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
            "jti": "forged",
        },
        "some-other-key",
        algorithm="HS256",
    )
    with pytest.raises(AuthenticationError) as exc:
        tokens.verify(forged)
    assert exc.value.code == "invalid_token"


def test_unsigned_token_is_rejected(tokens: TokenService, settings: Settings) -> None:
    forged = jwt.encode(
        {
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "sub": "user_1",
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
        },
        key="",
        algorithm="none",
    )
    with pytest.raises(AuthenticationError):
        tokens.verify(forged)
