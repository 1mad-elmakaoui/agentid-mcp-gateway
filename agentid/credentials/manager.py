"""Credential resolution.

The gateway — not the client, not the agent — owns downstream credentials
(architecture §12, invariant 7). For every proxied call the manager:

1. mints a short-lived, single-audience token identifying the execution
   identity to that one MCP server;
2. resolves the server's own credential (OAuth token, API key, service-account
   secret), refreshing it if it has expired;
3. returns the headers to attach — and nothing that a caller could echo back
   into a response body.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..config import Settings, get_settings
from ..context import RequestContext
from ..errors import CredentialError
from ..identity.tokens import TokenService
from ..models import Credential, CredentialType, IdentityType, McpServer, as_aware
from . import api_keys as api_key_credentials
from . import oauth as oauth_credentials
from .refresh import RefreshRegistry, payload_from_secret
from .token_cache import TokenCache
from .token_exchange import exchange_for_downstream
from .vault import LocalVault, SecretMaterial, get_vault

#: Sentinel owner for a credential that belongs to the server, not to a caller.
SERVER_DEFAULT_OWNER = IdentityType.GATEWAY

_BUILDERS = {
    CredentialType.OAUTH: oauth_credentials.build_secret,
    CredentialType.API_KEY: api_key_credentials.build_secret,
    CredentialType.SERVICE_ACCOUNT: api_key_credentials.build_secret,
}


@dataclass(slots=True)
class ResolvedCredential:
    """What the proxy attaches to a downstream request."""

    headers: dict[str, str] = field(default_factory=dict)
    #: Where the downstream credential came from, for audit. Never the secret.
    source: str = "gateway_token"
    credential_id: str | None = None
    expires_at: datetime | None = None

    def audit_fields(self) -> dict[str, Any]:
        return {
            "credential_source": self.source,
            "credential_id": self.credential_id,
            # Deliberately no secret material, in any form.
        }


class CredentialManager:
    def __init__(
        self,
        *,
        settings: Settings | None = None,
        vault: LocalVault | None = None,
        tokens: TokenService | None = None,
        refresh_registry: RefreshRegistry | None = None,
        cache: TokenCache[SecretMaterial] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.vault = vault or get_vault(self.settings)
        self.tokens = tokens or TokenService(self.settings)
        self.refresh_registry = refresh_registry or RefreshRegistry()
        self.cache: TokenCache[SecretMaterial] = cache or TokenCache(default_ttl_seconds=300)

    # -- resolution ------------------------------------------------------
    def resolve(
        self, db: DbSession, ctx: RequestContext, server: McpServer
    ) -> ResolvedCredential:
        downstream_token = exchange_for_downstream(
            ctx,
            server_name=server.name,
            audience=server.audience,
            tool=ctx.tool,
            settings=self.settings,
            tokens=self.tokens,
        )
        resolved = ResolvedCredential(
            headers={
                "Authorization": f"Bearer {downstream_token}",
                "X-AgentID-Request-Id": ctx.request_id,
            }
        )

        if server.credential_type == CredentialType.NONE:
            return resolved

        record = self._find_credential(db, ctx, server)
        if record is None:
            raise CredentialError(
                f"no {server.credential_type.value} credential registered for {server.name}",
                code="credential_not_found",
                server=server.name,
            )

        secret = self._materialise(db, server, record)
        header = secret.as_header()
        if header is not None:
            resolved.headers[header[0]] = header[1]
        resolved.source = f"{server.credential_type.value}:{record.owner_type.value}"
        resolved.credential_id = record.id
        resolved.expires_at = secret.expires_at
        return resolved

    def _find_credential(
        self, db: DbSession, ctx: RequestContext, server: McpServer
    ) -> Credential | None:
        """Most specific credential wins: execution identity, then server default."""
        candidates: list[tuple[IdentityType, str]] = []
        if ctx.service_account_id:
            candidates.append((IdentityType.SERVICE_ACCOUNT, ctx.service_account_id))
        if ctx.user_id:
            candidates.append((IdentityType.USER, ctx.user_id))
        if ctx.agent_id:
            candidates.append((IdentityType.AGENT, ctx.agent_id))
        candidates.append((SERVER_DEFAULT_OWNER, server.id))

        for owner_type, owner_id in candidates:
            record = db.scalar(
                select(Credential).where(
                    Credential.server_id == server.id,
                    Credential.owner_type == owner_type,
                    Credential.owner_id == owner_id,
                )
            )
            if record is not None:
                return record
        return None

    def _materialise(
        self, db: DbSession, server: McpServer, record: Credential
    ) -> SecretMaterial:
        cache_key = f"{record.id}:{record.updated_at.isoformat() if record.updated_at else ''}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        payload = self.vault.open(record.ciphertext)
        builder = _BUILDERS.get(record.credential_type)
        if builder is None:  # pragma: no cover - guarded by CredentialType
            raise CredentialError(
                f"unsupported credential type {record.credential_type}",
                code="unsupported_credential_type",
            )
        try:
            secret = builder(payload)
        except KeyError as exc:
            raise CredentialError(str(exc), code="malformed_credential") from exc

        if _is_expired(secret, record):
            secret = self.refresh_registry.refresh(server.name, secret)
            self._persist(db, record, secret)
            self.cache.invalidate(cache_key)
            cache_key = f"{record.id}:{record.updated_at.isoformat() if record.updated_at else ''}"

        self.cache.set(cache_key, secret, expires_at=secret.expires_at)
        return secret

    def _persist(self, db: DbSession, record: Credential, secret: SecretMaterial) -> None:
        record.ciphertext = self.vault.seal(payload_from_secret(secret))
        record.expires_at = secret.expires_at
        if secret.refresh_token:
            record.refresh_ciphertext = self.vault.seal({"refresh_token": secret.refresh_token})
        db.flush()

    # -- administration --------------------------------------------------
    def store(
        self,
        db: DbSession,
        *,
        server: McpServer,
        credential_type: CredentialType,
        payload: dict[str, Any],
        owner_type: IdentityType = SERVER_DEFAULT_OWNER,
        owner_id: str | None = None,
        expires_at: datetime | None = None,
    ) -> Credential:
        owner_id = owner_id or server.id
        record = db.scalar(
            select(Credential).where(
                Credential.server_id == server.id,
                Credential.owner_type == owner_type,
                Credential.owner_id == owner_id,
            )
        )
        ciphertext = self.vault.seal(payload)
        if record is None:
            record = Credential(
                server_id=server.id,
                owner_type=owner_type,
                owner_id=owner_id,
                credential_type=credential_type,
                ciphertext=ciphertext,
                expires_at=expires_at,
            )
            db.add(record)
        else:
            record.credential_type = credential_type
            record.ciphertext = ciphertext
            record.expires_at = expires_at
        db.flush()
        self.cache.clear()
        return record

    def delete(self, db: DbSession, credential_id: str) -> None:
        record = db.get(Credential, credential_id)
        if record is not None:
            db.delete(record)
            db.flush()
            self.cache.clear()


def _is_expired(secret: SecretMaterial, record: Credential) -> bool:
    expires = secret.expires_at or as_aware(record.expires_at)
    if expires is None:
        return False
    if expires.tzinfo is None:  # pragma: no cover - normalised by as_aware
        expires = expires.replace(tzinfo=UTC)
    return expires <= datetime.now(UTC)
