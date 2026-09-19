"""Policy documents.

A policy bundle is a small YAML/JSON file describing roles:

.. code-block:: yaml

    roles:
      - role: developer
        description: Day-to-day engineering access
        allow:
          - github.read
          - github.create_issue
          - database.read
        deny:
          - kubernetes.delete_namespace
          - database.drop
          - production.deploy

Bundles are declarative: loading one replaces the listed roles' entries so the
file stays the source of truth.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy.orm import Session as DbSession

from ..errors import ValidationError
from ..models import Role
from .rbac import upsert_role


@dataclass(slots=True)
class PolicyDocument:
    role: str
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    description: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> PolicyDocument:
        name = raw.get("role") or raw.get("name")
        if not name:
            raise ValidationError("policy entry is missing a 'role' name", code="invalid_policy")
        allow = list(raw.get("allow") or [])
        deny = list(raw.get("deny") or [])
        if not isinstance(allow, list) or not isinstance(deny, list):
            raise ValidationError("'allow' and 'deny' must be lists", code="invalid_policy")
        return cls(role=str(name), allow=allow, deny=deny, description=raw.get("description"))

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"role": self.role, "allow": self.allow, "deny": self.deny}
        if self.description:
            payload["description"] = self.description
        return payload


class PolicyBundle:
    def __init__(self, policies: list[PolicyDocument]) -> None:
        self.policies = policies

    @classmethod
    def from_obj(cls, raw: Any) -> PolicyBundle:
        if isinstance(raw, dict):
            entries = raw.get("roles") or raw.get("policies")
            if entries is None:
                raise ValidationError(
                    "policy bundle must contain a 'roles' list", code="invalid_policy"
                )
        elif isinstance(raw, list):
            entries = raw
        else:
            raise ValidationError("unsupported policy document", code="invalid_policy")
        return cls([PolicyDocument.from_dict(entry) for entry in entries])

    @classmethod
    def load(cls, path: str | Path) -> PolicyBundle:
        p = Path(path)
        if not p.exists():
            raise ValidationError(f"policy file not found: {p}", code="policy_not_found")
        text = p.read_text(encoding="utf-8")
        raw = json.loads(text) if p.suffix == ".json" else yaml.safe_load(text)
        return cls.from_obj(raw)

    def apply(self, db: DbSession) -> list[Role]:
        return [
            upsert_role(
                db,
                policy.role,
                allow=policy.allow,
                deny=policy.deny,
                description=policy.description,
            )
            for policy in self.policies
        ]

    def to_dict(self) -> dict[str, Any]:
        return {"roles": [p.to_dict() for p in self.policies]}


def load_policy_file(db: DbSession, path: str | Path) -> list[Role]:
    return PolicyBundle.load(path).apply(db)
