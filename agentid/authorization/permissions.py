"""Permission names and matching.

Permissions are dotted names — ``github.create_issue`` — and patterns may use
``*`` for a single segment or as a trailing catch-all:

>>> matches("github.*", "github.create_issue")
True
>>> matches("github.*", "github.issues.create")
False
>>> matches("github.**", "github.issues.create")
True
>>> matches("*", "anything.at.all")
True
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

SEPARATOR = "."
SINGLE = "*"
RECURSIVE = "**"


def matches(pattern: str, permission: str) -> bool:
    if pattern == permission:
        return True
    if pattern in {SINGLE, RECURSIVE}:
        return True
    p_parts = pattern.split(SEPARATOR)
    v_parts = permission.split(SEPARATOR)
    for index, part in enumerate(p_parts):
        if part == RECURSIVE:
            # Trailing ``**`` swallows the remainder.
            return index <= len(v_parts)
        if index >= len(v_parts):
            return False
        if part == SINGLE:
            continue
        if part != v_parts[index]:
            return False
    return len(p_parts) == len(v_parts)


def any_matches(patterns: Iterable[str], permission: str) -> str | None:
    """Return the first pattern that matches, or ``None``."""
    for pattern in patterns:
        if matches(pattern, permission):
            return pattern
    return None


@dataclass(slots=True)
class PermissionSet:
    """The allow/deny patterns attached to one identity.

    Deny always wins over allow, regardless of specificity.
    """

    allow: set[str] = field(default_factory=set)
    deny: set[str] = field(default_factory=set)
    #: Names of the roles that contributed, used in decision explanations.
    sources: tuple[str, ...] = ()

    def permits(self, permission: str) -> bool:
        return self.denied_by(permission) is None and self.allowed_by(permission) is not None

    def allowed_by(self, permission: str) -> str | None:
        return any_matches(sorted(self.allow), permission)

    def denied_by(self, permission: str) -> str | None:
        return any_matches(sorted(self.deny), permission)

    def merge(self, other: PermissionSet) -> PermissionSet:
        """Union of grants — used when an identity holds several roles."""
        return PermissionSet(
            allow=self.allow | other.allow,
            deny=self.deny | other.deny,
            sources=tuple(dict.fromkeys(self.sources + other.sources)),
        )

    def intersect(self, other: PermissionSet) -> PermissionSet:
        """Effective permissions of a delegation chain.

        Patterns cannot be intersected syntactically, so the result keeps both
        sides' patterns and relies on :meth:`permits` only being consulted
        through :func:`effective_permits`. Denies from either side are unioned,
        which is the safe direction.
        """
        return PermissionSet(
            allow=self.allow & other.allow,
            deny=self.deny | other.deny,
            sources=tuple(dict.fromkeys(self.sources + other.sources)),
        )

    def resolved(self, universe: Iterable[str]) -> set[str]:
        """Expand patterns against a concrete set of permission names."""
        return {name for name in universe if self.permits(name)}

    def __bool__(self) -> bool:
        return bool(self.allow or self.deny)


def effective_permits(permission: str, *sets: PermissionSet) -> bool:
    """``True`` only when every set permits the permission.

    This is the pattern-safe form of ``user ∩ agent``: an agent never gains a
    permission its delegating user lacks, and either side may veto.
    """
    return all(ps.permits(permission) for ps in sets)


EMPTY = PermissionSet()
