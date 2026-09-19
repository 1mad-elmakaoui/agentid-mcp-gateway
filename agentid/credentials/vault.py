"""Encrypted storage for downstream secrets.

Secrets are sealed with Fernet (AES-128-CBC + HMAC) under a key derived from
``AGENTID_CREDENTIAL_ENCRYPTION_KEY``. The plaintext exists only inside the
gateway process, for the duration of one downstream call (invariant 7).

In production the ``Vault`` protocol is the seam where a real secrets manager
(HashiCorp Vault, AWS Secrets Manager, ...) is plugged in; ``LocalVault`` is
the batteries-included implementation.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from cryptography.fernet import Fernet, InvalidToken

from ..config import Settings, get_settings
from ..errors import CredentialError


@dataclass(slots=True)
class SecretMaterial:
    """A decrypted credential. Never serialise this into a response."""

    kind: str
    value: str
    expires_at: datetime | None = None
    refresh_token: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def as_header(self) -> tuple[str, str] | None:
        """How the secret is attached to the downstream request."""
        if self.kind == "oauth":
            return ("X-Downstream-Authorization", f"Bearer {self.value}")
        if self.kind == "api_key":
            return ("X-Downstream-Api-Key", self.value)
        return None

    def redacted(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": "***redacted***", "expires_at": self.expires_at}

    def __repr__(self) -> str:  # pragma: no cover - safety net for logs
        return f"<SecretMaterial kind={self.kind} value=***redacted***>"

    __str__ = __repr__


def _derive_key(secret: str) -> bytes:
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


class Vault(Protocol):  # pragma: no cover - structural type
    def seal(self, payload: dict[str, Any]) -> str: ...

    def open(self, ciphertext: str) -> dict[str, Any]: ...


class LocalVault:
    """Fernet-based vault backed by the gateway's own database."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._fernet = Fernet(_derive_key(self.settings.vault_key))

    def seal(self, payload: dict[str, Any]) -> str:
        return self._fernet.encrypt(json.dumps(payload).encode("utf-8")).decode("ascii")

    def open(self, ciphertext: str) -> dict[str, Any]:
        try:
            raw = self._fernet.decrypt(ciphertext.encode("ascii"))
        except InvalidToken as exc:
            raise CredentialError(
                "stored credential could not be decrypted", code="credential_undecryptable"
            ) from exc
        return json.loads(raw.decode("utf-8"))


def get_vault(settings: Settings | None = None) -> LocalVault:
    return LocalVault(settings)
