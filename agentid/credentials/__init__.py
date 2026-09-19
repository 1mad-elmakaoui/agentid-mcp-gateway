"""Credential management: vault, resolution, refresh and token exchange."""

from .manager import SERVER_DEFAULT_OWNER, CredentialManager, ResolvedCredential
from .refresh import CallableRefreshProvider, NullRefreshProvider, RefreshRegistry
from .token_cache import TokenCache
from .token_exchange import (
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_JWT,
    ExchangeResult,
    exchange_for_delegation,
    exchange_for_downstream,
)
from .vault import LocalVault, SecretMaterial, get_vault

__all__ = [
    "GRANT_TYPE_TOKEN_EXCHANGE",
    "SERVER_DEFAULT_OWNER",
    "TOKEN_TYPE_JWT",
    "CallableRefreshProvider",
    "CredentialManager",
    "ExchangeResult",
    "LocalVault",
    "NullRefreshProvider",
    "RefreshRegistry",
    "ResolvedCredential",
    "SecretMaterial",
    "TokenCache",
    "exchange_for_delegation",
    "exchange_for_downstream",
    "get_vault",
]
