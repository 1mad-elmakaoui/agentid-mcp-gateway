"""Static API-key credentials for downstream servers."""

from __future__ import annotations

from typing import Any

from .vault import SecretMaterial


def build_secret(payload: dict[str, Any]) -> SecretMaterial:
    value = payload.get("api_key") or payload.get("value")
    if not value:
        raise KeyError("api_key credential payload has no 'api_key'")
    return SecretMaterial(
        kind="api_key",
        value=str(value),
        extra={k: v for k, v in payload.items() if k not in {"api_key", "value"}},
    )


def make_payload(api_key: str, **extra: Any) -> dict[str, Any]:
    return {"api_key": api_key, **extra}
