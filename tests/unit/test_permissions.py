"""Permission matching and the user ∩ agent intersection."""

from __future__ import annotations

import pytest

from agentid.authorization.permissions import PermissionSet, effective_permits, matches


@pytest.mark.parametrize(
    ("pattern", "permission", "expected"),
    [
        ("github.create_issue", "github.create_issue", True),
        ("github.create_issue", "github.get_issue", False),
        ("github.*", "github.create_issue", True),
        ("github.*", "github.issues.create", False),
        ("github.**", "github.issues.create", True),
        ("github.**", "github.create_issue", True),
        ("*", "anything.at.all", True),
        ("*.read", "github.read", True),
        ("*.read", "github.write", False),
        ("database.*", "github.read", False),
    ],
)
def test_matches(pattern: str, permission: str, expected: bool) -> None:
    assert matches(pattern, permission) is expected


def test_deny_wins_over_allow() -> None:
    pset = PermissionSet(allow={"github.**"}, deny={"github.delete_repo"})
    assert pset.permits("github.create_issue")
    assert not pset.permits("github.delete_repo")


def test_deny_wins_even_when_more_general() -> None:
    pset = PermissionSet(allow={"kubernetes.delete_namespace"}, deny={"kubernetes.**"})
    assert not pset.permits("kubernetes.delete_namespace")


def test_merge_unions_grants_and_denies() -> None:
    a = PermissionSet(allow={"github.read"}, deny={"database.drop"}, sources=("developer",))
    b = PermissionSet(allow={"database.read"}, deny={"production.deploy"}, sources=("analyst",))
    merged = a.merge(b)
    assert merged.allow == {"github.read", "database.read"}
    assert merged.deny == {"database.drop", "production.deploy"}
    assert merged.sources == ("developer", "analyst")


def test_effective_permits_is_the_intersection() -> None:
    user = PermissionSet(allow={"github.read", "github.create_issue", "database.read"})
    agent = PermissionSet(allow={"github.read", "github.create_issue", "kubernetes.read"})

    assert effective_permits("github.create_issue", user, agent)
    # The agent holds kubernetes.read; the user does not, so the chain does not.
    assert not effective_permits("kubernetes.read", user, agent)
    # The user holds database.read; the agent does not, so the chain does not.
    assert not effective_permits("database.read", user, agent)


def test_intersection_denies_union() -> None:
    user = PermissionSet(allow={"github.read"}, deny={"github.delete"})
    agent = PermissionSet(allow={"github.read"}, deny={"database.drop"})
    combined = user.intersect(agent)
    assert combined.allow == {"github.read"}
    assert combined.deny == {"github.delete", "database.drop"}


def test_resolved_expands_patterns() -> None:
    pset = PermissionSet(allow={"github.*"}, deny={"github.delete_repo"})
    universe = {"github.read", "github.delete_repo", "database.read"}
    assert pset.resolved(universe) == {"github.read"}
