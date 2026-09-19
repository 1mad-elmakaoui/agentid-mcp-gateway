"""Error types shared across the gateway.

Every error carries a machine-readable ``code`` so audit events and API
responses agree on *why* something was rejected.
"""

from __future__ import annotations


class AgentIDError(Exception):
    """Base class for all AgentID errors."""

    status_code: int = 500
    code: str = "internal_error"

    def __init__(
        self, message: str | None = None, *, code: str | None = None, **details: object
    ) -> None:
        super().__init__(message or self.code)
        self.message = message or self.code
        if code:
            self.code = code
        self.details = details

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"error": self.code, "message": self.message}
        if self.details:
            payload["details"] = self.details
        return payload


class AuthenticationError(AgentIDError):
    """The caller could not be authenticated (invariant 1)."""

    status_code = 401
    code = "unauthenticated"


class AuthorizationError(AgentIDError):
    """The caller is known but not allowed to perform the action."""

    status_code = 403
    code = "forbidden"


class PersonaViolation(AuthorizationError):
    """A non-user identity attempted to act as a human user (invariant 3)."""

    code = "persona_violation"


class DelegationError(AuthorizationError):
    """A delegation chain is missing, expired or not permitted."""

    code = "invalid_delegation"


class CredentialError(AgentIDError):
    """A downstream credential could not be resolved."""

    status_code = 502
    code = "credential_unavailable"


class NotFoundError(AgentIDError):
    status_code = 404
    code = "not_found"


class ConflictError(AgentIDError):
    status_code = 409
    code = "conflict"


class ValidationError(AgentIDError):
    status_code = 422
    code = "invalid_request"


class RateLimitExceeded(AgentIDError):
    status_code = 429
    code = "rate_limited"


class DownstreamError(AgentIDError):
    status_code = 502
    code = "downstream_error"
