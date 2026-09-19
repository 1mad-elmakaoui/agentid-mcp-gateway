"""Gateway token issuing and verification.

Two token families exist and must never be confused:

``client tokens``
    Presented by MCP clients to the gateway. Audience ``agentid-gateway``.
    A delegated client token carries ``sub`` (the user) and ``act.sub`` (the
    agent), as in RFC 8693 §4.1.

``downstream tokens``
    Minted per call by the gateway for one specific MCP server. Audience
    ``agentid-mcp:<server>``, lifetime measured in seconds. A client token can
    never be replayed downstream because the audiences differ.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from ..config import Settings, get_settings
from ..errors import AuthenticationError
from ..models import Persona
from .secrets import random_id


class TokenType:
    ACCESS = "access"
    DELEGATED = "delegated"
    DOWNSTREAM = "downstream"


@dataclass(slots=True)
class TokenClaims:
    """Decoded, validated claims of a gateway token."""

    sub: str
    persona: Persona
    token_type: str
    audience: str
    issuer: str
    jti: str
    issued_at: datetime
    expires_at: datetime
    act_sub: str | None = None
    subject_type: str = "user"
    session_id: str | None = None
    delegation_id: str | None = None
    service_account_id: str | None = None
    scopes: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_delegated(self) -> bool:
        return self.act_sub is not None

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> TokenClaims:
        act = payload.get("act") or {}
        scope = payload.get("scope") or ""
        aud = payload.get("aud")
        if isinstance(aud, list):  # pragma: no cover - defensive
            aud = aud[0]
        return cls(
            sub=str(payload["sub"]),
            persona=Persona(payload.get("persona", Persona.USER.value)),
            token_type=str(payload.get("typ", TokenType.ACCESS)),
            audience=str(aud),
            issuer=str(payload.get("iss", "")),
            jti=str(payload.get("jti", "")),
            issued_at=datetime.fromtimestamp(int(payload["iat"]), tz=UTC),
            expires_at=datetime.fromtimestamp(int(payload["exp"]), tz=UTC),
            act_sub=str(act["sub"]) if act.get("sub") else None,
            subject_type=str(payload.get("sub_type", "user")),
            session_id=payload.get("sid"),
            delegation_id=payload.get("did"),
            service_account_id=payload.get("execution_identity"),
            scopes=tuple(scope.split()) if scope else (),
            raw=payload,
        )


class TokenService:
    """Signs and verifies gateway tokens."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    # -- issuing ---------------------------------------------------------
    def _encode(self, payload: dict[str, Any]) -> str:
        return jwt.encode(
            payload, self.settings.secret_key, algorithm=self.settings.jwt_algorithm
        )

    def _base_payload(
        self,
        *,
        subject: str,
        persona: Persona,
        token_type: str,
        audience: str,
        ttl_seconds: int,
        scopes: tuple[str, ...] | list[str] = (),
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        payload: dict[str, Any] = {
            "iss": self.settings.jwt_issuer,
            "aud": audience,
            "sub": subject,
            "persona": persona.value,
            "typ": token_type,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
            "jti": random_id(12),
        }
        if scopes:
            payload["scope"] = " ".join(scopes)
        return payload

    def issue_access_token(
        self,
        *,
        subject: str,
        persona: Persona,
        subject_type: str,
        session_id: str | None = None,
        scopes: tuple[str, ...] | list[str] = ("mcp:tools",),
        ttl_seconds: int | None = None,
    ) -> tuple[str, TokenClaims]:
        payload = self._base_payload(
            subject=subject,
            persona=persona,
            token_type=TokenType.ACCESS,
            audience=self.settings.jwt_audience,
            ttl_seconds=ttl_seconds or self.settings.access_token_ttl_seconds,
            scopes=scopes,
        )
        payload["sub_type"] = subject_type
        if session_id:
            payload["sid"] = session_id
        return self._encode(payload), TokenClaims.from_payload(payload)

    def issue_delegated_token(
        self,
        *,
        user_id: str,
        agent_id: str,
        session_id: str | None = None,
        delegation_id: str | None = None,
        scopes: tuple[str, ...] | list[str] = ("mcp:tools",),
        ttl_seconds: int | None = None,
    ) -> tuple[str, TokenClaims]:
        """Issue ``sub`` = user, ``act.sub`` = agent (architecture §10)."""
        payload = self._base_payload(
            subject=user_id,
            persona=Persona.USER,
            token_type=TokenType.DELEGATED,
            audience=self.settings.jwt_audience,
            ttl_seconds=ttl_seconds or self.settings.delegated_token_ttl_seconds,
            scopes=scopes,
        )
        payload["sub_type"] = "user"
        payload["act"] = {"sub": agent_id, "sub_type": "agent"}
        if session_id:
            payload["sid"] = session_id
        if delegation_id:
            payload["did"] = delegation_id
        return self._encode(payload), TokenClaims.from_payload(payload)

    def issue_downstream_token(
        self,
        *,
        server_name: str,
        audience: str | None = None,
        user_id: str | None = None,
        agent_id: str | None = None,
        service_account_id: str | None = None,
        persona: Persona = Persona.USER,
        tool: str | None = None,
        request_id: str | None = None,
        scopes: tuple[str, ...] | list[str] = (),
        ttl_seconds: int | None = None,
    ) -> str:
        """Mint the short-lived credential a downstream MCP server verifies.

        The subject is the *execution identity*: the service account when one is
        in play, otherwise the user, otherwise the agent. ``act`` preserves the
        acting agent so the downstream audit trail keeps both identities.
        """
        subject = service_account_id or user_id or agent_id
        if subject is None:  # pragma: no cover - guarded by callers
            raise AuthenticationError("cannot mint a downstream token without a subject")
        aud = audience or f"{self.settings.downstream_audience_prefix}:{server_name}"
        payload = self._base_payload(
            subject=subject,
            persona=persona,
            token_type=TokenType.DOWNSTREAM,
            audience=aud,
            ttl_seconds=ttl_seconds or self.settings.downstream_token_ttl_seconds,
            scopes=scopes,
        )
        if agent_id:
            payload["act"] = {"sub": agent_id, "sub_type": "agent"}
        if user_id:
            payload["on_behalf_of"] = user_id
        if service_account_id:
            payload["execution_identity"] = service_account_id
            payload["sub_type"] = "service_account"
        elif user_id and subject == user_id:
            payload["sub_type"] = "user"
        else:
            payload["sub_type"] = "agent"
        if tool:
            payload["tool"] = tool
        if request_id:
            payload["rid"] = request_id
        return self._encode(payload)

    # -- verification ----------------------------------------------------
    def verify(self, token: str, *, audience: str | None = None) -> TokenClaims:
        try:
            payload = jwt.decode(
                token,
                self.settings.secret_key,
                algorithms=[self.settings.jwt_algorithm],
                audience=audience or self.settings.jwt_audience,
                issuer=self.settings.jwt_issuer,
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthenticationError("token expired", code="token_expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise AuthenticationError("token audience mismatch", code="invalid_audience") from exc
        except jwt.PyJWTError as exc:
            raise AuthenticationError(f"invalid token: {exc}", code="invalid_token") from exc
        return TokenClaims.from_payload(payload)
