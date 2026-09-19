"""OAuth credential payloads.

The gateway stores the access token (and refresh token, when present) sealed in
the vault. Refreshing is delegated to :mod:`agentid.credentials.refresh`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from .vault import SecretMaterial


def build_secret(payload: dict[str, Any]) -> SecretMaterial:
    token = payload.get("access_token") or payload.get("value")
    if not token:
        raise KeyError("oauth credential payload has no 'access_token'")
    expires_at = payload.get("expires_at")
    parsed: datetime | None = None
    if isinstance(expires_at, str):
        parsed = datetime.fromisoformat(expires_at)
    elif isinstance(expires_at, (int, float)):
        parsed = datetime.fromtimestamp(expires_at, tz=UTC)
    return SecretMaterial(
        kind="oauth",
        value=str(token),
        expires_at=parsed,
        refresh_token=payload.get("refresh_token"),
        extra={"token_type": payload.get("token_type", "Bearer"), "scope": payload.get("scope")},
    )


def make_payload(
    access_token: str,
    *,
    refresh_token: str | None = None,
    expires_in: int | None = None,
    scope: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"access_token": access_token, "token_type": "Bearer"}
    if refresh_token:
        payload["refresh_token"] = refresh_token
    if expires_in:
        payload["expires_at"] = (
            datetime.now(UTC) + timedelta(seconds=expires_in)
        ).isoformat()
    if scope:
        payload["scope"] = scope
    return payload
