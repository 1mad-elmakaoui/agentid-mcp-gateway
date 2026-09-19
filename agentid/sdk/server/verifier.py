"""Verification of gateway-issued credentials.

A downstream MCP server checks signature, audience, expiration, issuer and
claims — and nothing else about identity. Resource-level authorization stays
the server's own job (invariant 10).
"""

from __future__ import annotations

import os

import jwt

from .claims import GatewayClaims


class VerificationError(Exception):
    """The presented credential is not a valid gateway token for this server."""

    def __init__(self, message: str, *, code: str = "invalid_token") -> None:
        super().__init__(message)
        self.code = code


class TokenVerifier:
    """Verifies the short-lived token the gateway mints for one server.

    ``audience`` must be this server's own audience. Because the gateway issues
    a distinct audience per server, a token minted for another server — or a
    client's own gateway token — fails here.
    """

    def __init__(
        self,
        *,
        secret: str,
        audience: str,
        issuer: str = "agentid",
        algorithms: list[str] | None = None,
        leeway_seconds: int = 5,
    ) -> None:
        self.secret = secret
        self.audience = audience
        self.issuer = issuer
        self.algorithms = algorithms or ["HS256"]
        self.leeway_seconds = leeway_seconds

    @classmethod
    def from_env(cls, *, audience: str | None = None) -> TokenVerifier:
        secret = os.environ.get("AGENTID_SECRET_KEY", "dev-only-insecure-secret-change-me")
        aud = audience or os.environ.get("AGENTID_SERVER_AUDIENCE")
        if not aud:
            raise VerificationError(
                "AGENTID_SERVER_AUDIENCE is not configured", code="misconfigured"
            )
        return cls(
            secret=secret,
            audience=aud,
            issuer=os.environ.get("AGENTID_JWT_ISSUER", "agentid"),
        )

    def verify(self, token: str) -> GatewayClaims:
        try:
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway_seconds,
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise VerificationError("credential expired", code="token_expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise VerificationError(
                "credential was not issued for this server", code="invalid_audience"
            ) from exc
        except jwt.InvalidIssuerError as exc:
            raise VerificationError("unknown issuer", code="invalid_issuer") from exc
        except jwt.PyJWTError as exc:
            raise VerificationError(f"invalid credential: {exc}") from exc

        if payload.get("typ") != "downstream":
            # A client's gateway token must never be accepted downstream.
            raise VerificationError(
                "credential is not a downstream token", code="wrong_token_type"
            )
        return GatewayClaims.from_payload(payload)

    def verify_header(self, header_value: str | None) -> GatewayClaims:
        if not header_value:
            raise VerificationError("missing Authorization header", code="missing_credential")
        scheme, _, token = header_value.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise VerificationError("expected a Bearer credential", code="malformed_credential")
        return self.verify(token.strip())
