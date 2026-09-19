"""API keys for machine callers (agents and service accounts).

Format: ``<prefix><key_id>.<secret>``. The key id is stored in clear for an
indexed lookup; the secret is only ever stored hashed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..config import Settings, get_settings
from ..errors import AuthenticationError
from ..models import ApiKey, IdentityType, utcnow
from .secrets import hash_secret, random_id, random_token, verify


@dataclass(slots=True)
class IssuedApiKey:
    record: ApiKey
    #: Plaintext key. Returned once, never stored, never re-derivable.
    plaintext: str


def issue_api_key(
    db: DbSession,
    *,
    name: str,
    owner_type: IdentityType,
    owner_id: str,
    ttl_seconds: int | None = None,
    settings: Settings | None = None,
) -> IssuedApiKey:
    settings = settings or get_settings()
    if owner_type == IdentityType.USER:
        # Users authenticate interactively; a long-lived user key would blur the
        # user/non-user persona boundary.
        raise AuthenticationError(
            "api keys may only be issued to agents or service accounts",
            code="api_key_persona_violation",
        )
    key_id = random_id(8)
    secret = random_token(32)
    record = ApiKey(
        name=name,
        key_id=key_id,
        secret_hash=hash_secret(secret),
        owner_type=owner_type,
        owner_id=owner_id,
        expires_at=utcnow() + timedelta(seconds=ttl_seconds) if ttl_seconds else None,
    )
    db.add(record)
    db.flush()
    return IssuedApiKey(record=record, plaintext=f"{settings.api_key_prefix}{key_id}.{secret}")


def parse_api_key(raw: str, *, settings: Settings | None = None) -> tuple[str, str]:
    settings = settings or get_settings()
    if not raw.startswith(settings.api_key_prefix):
        raise AuthenticationError("malformed api key", code="invalid_api_key")
    body = raw[len(settings.api_key_prefix) :]
    key_id, _, secret = body.partition(".")
    if not key_id or not secret:
        raise AuthenticationError("malformed api key", code="invalid_api_key")
    return key_id, secret


def verify_api_key(db: DbSession, raw: str, *, settings: Settings | None = None) -> ApiKey:
    key_id, secret = parse_api_key(raw, settings=settings)
    record = db.scalar(select(ApiKey).where(ApiKey.key_id == key_id))
    if record is None or not verify(secret, record.secret_hash):
        raise AuthenticationError("invalid api key", code="invalid_api_key")
    if not record.is_active:
        raise AuthenticationError("api key revoked or expired", code="api_key_inactive")
    record.last_used_at = utcnow()
    db.flush()
    return record


def revoke_api_key(db: DbSession, api_key_id: str) -> None:
    record = db.get(ApiKey, api_key_id)
    if record is not None and record.revoked_at is None:
        record.revoked_at = utcnow()
        db.flush()


def list_api_keys(db: DbSession, *, owner_id: str | None = None) -> list[ApiKey]:
    stmt = select(ApiKey)
    if owner_id:
        stmt = stmt.where(ApiKey.owner_id == owner_id)
    return list(db.scalars(stmt.order_by(ApiKey.created_at)))
