"""Authorization: RBAC, policies, and the decision engine."""

from .decisions import Decision, Effect, Reason
from .engine import REQUIRED_TOOL_SCOPE, AuthorizationEngine, ResolvedPrincipals
from .permissions import PermissionSet, effective_permits, matches
from .policies import PolicyBundle, PolicyDocument, load_policy_file
from .rbac import (
    all_permission_names,
    get_role,
    list_roles,
    permissions_for_agent,
    permissions_for_service_account,
    permissions_for_user,
    upsert_permission,
    upsert_role,
)

__all__ = [
    "REQUIRED_TOOL_SCOPE",
    "AuthorizationEngine",
    "Decision",
    "Effect",
    "PermissionSet",
    "PolicyBundle",
    "PolicyDocument",
    "Reason",
    "ResolvedPrincipals",
    "all_permission_names",
    "effective_permits",
    "get_role",
    "list_roles",
    "load_policy_file",
    "matches",
    "permissions_for_agent",
    "permissions_for_service_account",
    "permissions_for_user",
    "upsert_permission",
    "upsert_role",
]
