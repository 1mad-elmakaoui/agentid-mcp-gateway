"""Credential refresh.

Refresh is pluggable: a provider is registered per MCP server name (or a
default is used). The bundled provider simply reports that it cannot refresh,
which surfaces as a clear ``credential_expired`` error rather than a confusing
downstream 401.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from ..errors import CredentialError
from .vault import SecretMaterial


class RefreshProvider(Protocol):  # pragma: no cover - structural type
    def refresh(self, server_name: str, secret: SecretMaterial) -> SecretMaterial: ...


class NullRefreshProvider:
    def refresh(self, server_name: str, secret: SecretMaterial) -> SecretMaterial:
        raise CredentialError(
            f"credential for {server_name} is expired and cannot be refreshed",
            code="credential_expired",
            server=server_name,
        )


class CallableRefreshProvider:
    """Adapts a plain function into a refresh provider (handy for tests)."""

    def __init__(self, fn: Callable[[str, SecretMaterial], SecretMaterial]) -> None:
        self._fn = fn

    def refresh(self, server_name: str, secret: SecretMaterial) -> SecretMaterial:
        return self._fn(server_name, secret)


class RefreshRegistry:
    def __init__(self, default: RefreshProvider | None = None) -> None:
        self._default: RefreshProvider = default or NullRefreshProvider()
        self._providers: dict[str, RefreshProvider] = {}

    def register(self, server_name: str, provider: RefreshProvider) -> None:
        self._providers[server_name] = provider

    def unregister(self, server_name: str) -> None:
        self._providers.pop(server_name, None)

    def for_server(self, server_name: str) -> RefreshProvider:
        return self._providers.get(server_name, self._default)

    def refresh(self, server_name: str, secret: SecretMaterial) -> SecretMaterial:
        return self.for_server(server_name).refresh(server_name, secret)


def payload_from_secret(secret: SecretMaterial) -> dict[str, Any]:
    """Serialise a refreshed secret back into a storable payload."""
    payload: dict[str, Any] = {"value": secret.value}
    if secret.kind == "oauth":
        payload = {"access_token": secret.value, "token_type": "Bearer"}
        if secret.refresh_token:
            payload["refresh_token"] = secret.refresh_token
    elif secret.kind == "api_key":
        payload = {"api_key": secret.value}
    if secret.expires_at:
        payload["expires_at"] = secret.expires_at.isoformat()
    payload.update({k: v for k, v in secret.extra.items() if v is not None})
    return payload
