"""The authorization engine.

Authentication has already answered *who are you?* by the time this module
runs. It answers the separate question *are you allowed to do this?* and it
always runs **before** the request is routed to an MCP server (invariants 4
and 5).

Evaluation order, most restrictive first:

1. an authenticated identity must be present;
2. the persona must be coherent (no autonomous caller wearing a human's id);
3. the token must carry the required scope;
4. the tool and its server must exist and be enabled;
5. explicit denies from any participating identity;
6. the user must hold the permission (when a user is in the chain);
7. the agent must hold the permission — the ``user ∩ agent`` intersection;
8. the execution identity is resolved, and a service account requires an
   explicit grant plus its own permission.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session as DbSession

from ..config import Settings, get_settings
from ..context import RequestContext
from ..identity.agents import get_agent
from ..identity.service_accounts import may_use_service_account, resolve_service_account
from ..identity.users import get_user
from ..models import Agent, AgentKind, IdentityType, Persona, ServiceAccount, Tool, User
from .decisions import Decision, Reason
from .permissions import PermissionSet
from .rbac import (
    permissions_for_agent,
    permissions_for_service_account,
    permissions_for_user,
)

REQUIRED_TOOL_SCOPE = "mcp:tools"


@dataclass(slots=True)
class ResolvedPrincipals:
    user: User | None = None
    agent: Agent | None = None
    service_account: ServiceAccount | None = None
    user_permissions: PermissionSet = field(default_factory=PermissionSet)
    agent_permissions: PermissionSet = field(default_factory=PermissionSet)
    service_account_permissions: PermissionSet = field(default_factory=PermissionSet)


class AuthorizationEngine:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    # -- public API ------------------------------------------------------
    def authorize_tool(
        self,
        db: DbSession,
        ctx: RequestContext,
        tool: Tool,
        *,
        requested_service_account: str | None = None,
    ) -> Decision:
        base = {
            "tool": tool.qualified_name,
            "server": tool.server.name,
            "permission": tool.permission,
        }

        identity_check = self._check_identity(ctx)
        if identity_check is not None:
            return identity_check

        scope_check = self._check_scope(ctx, base)
        if scope_check is not None:
            return scope_check

        availability = self._check_availability(tool, base)
        if availability is not None:
            return availability

        principals, failure = self._resolve_principals(db, ctx, base)
        if failure is not None:
            return failure

        persona_check = self._check_persona(ctx, principals, base)
        if persona_check is not None:
            return persona_check

        permission = tool.permission

        # 5. Explicit denies win over everything else.
        for label, pset in (
            ("user", principals.user_permissions),
            ("agent", principals.agent_permissions),
        ):
            pattern = pset.denied_by(permission) if pset else None
            if pattern:
                return Decision.deny(
                    Reason.EXPLICIT_DENY,
                    policy=_policy_name(pset),
                    message=f"{label} policy explicitly denies {permission}",
                    details={"matched_pattern": pattern, "denied_by": label},
                    **base,
                )

        # 6. The delegating user must hold the permission.
        if principals.user is not None and not principals.user_permissions.permits(permission):
            return Decision.deny(
                Reason.MISSING_PERMISSION,
                policy=_policy_name(principals.user_permissions),
                message=f"user {principals.user.id} lacks {permission}",
                **base,
            )

        # 7. The agent must hold it too: effective = user ∩ agent.
        if principals.agent is not None and not principals.agent_permissions.permits(permission):
            reason = (
                Reason.AGENT_NOT_PERMITTED
                if principals.user is None
                else Reason.EXCEEDS_USER_PERMISSIONS
            )
            return Decision.deny(
                reason,
                policy=_policy_name(principals.agent_permissions),
                message=f"agent {principals.agent.name} lacks {permission}",
                **base,
            )

        if principals.user is None and principals.agent is None:
            sa = principals.service_account
            if sa is None:
                return Decision.deny(
                    Reason.UNAUTHENTICATED, message="no principal to authorize", **base
                )
            sa_permissions = principals.service_account_permissions
            if sa_permissions.denied_by(permission):
                return Decision.deny(
                    Reason.EXPLICIT_DENY,
                    policy=_policy_name(sa_permissions),
                    message=f"service account policy explicitly denies {permission}",
                    **base,
                )
            if not sa_permissions.permits(permission):
                return Decision.deny(
                    Reason.SERVICE_ACCOUNT_NOT_PERMITTED,
                    policy=_policy_name(sa_permissions),
                    message=f"service account {sa.name} lacks {permission}",
                    **base,
                )
            return Decision.allow(
                policy=_policy_name(sa_permissions),
                execution_identity=sa.id,
                service_account_id=sa.id,
                details={"service_account": sa.name},
                **base,
            )

        # 8. Execution identity.
        return self._resolve_execution_identity(
            db,
            ctx,
            tool,
            principals,
            requested_service_account=requested_service_account,
            base=base,
        )

    def authorize_service_account_use(
        self,
        db: DbSession,
        ctx: RequestContext,
        service_account_identifier: str,
    ) -> Decision:
        """Standalone check of `user|agent -> service account` (architecture §8)."""
        sa = resolve_service_account(db, service_account_identifier)
        if sa is None or not sa.is_active:
            return Decision.deny(
                Reason.SERVICE_ACCOUNT_NOT_AUTHORIZED,
                message=f"unknown or disabled service account: {service_account_identifier}",
            )
        grantee_type, grantee_id = _grantee_for(ctx)
        if grantee_id is None:
            return Decision.deny(Reason.UNAUTHENTICATED, message="no principal")
        if not may_use_service_account(
            db,
            grantee_type=grantee_type,
            grantee_id=grantee_id,
            service_account_id=sa.id,
        ):
            return Decision.deny(
                Reason.SERVICE_ACCOUNT_NOT_AUTHORIZED,
                message=f"{grantee_id} is not authorized to use {sa.name}",
                details={"service_account": sa.name},
            )
        return Decision.allow(
            execution_identity=sa.id,
            service_account_id=sa.id,
            details={"service_account": sa.name},
        )

    # -- steps -----------------------------------------------------------
    @staticmethod
    def _check_identity(ctx: RequestContext) -> Decision | None:
        if ctx.user_id is None and ctx.agent_id is None and ctx.service_account_id is None:
            return Decision.deny(
                Reason.UNAUTHENTICATED, message="request has no authenticated identity"
            )
        return None

    @staticmethod
    def _check_scope(ctx: RequestContext, base: dict[str, str]) -> Decision | None:
        if ctx.scopes and REQUIRED_TOOL_SCOPE not in ctx.scopes:
            return Decision.deny(
                Reason.MISSING_SCOPE,
                message=f"token is missing the {REQUIRED_TOOL_SCOPE} scope",
                details={"scopes": list(ctx.scopes)},
                **base,
            )
        return None

    @staticmethod
    def _check_availability(tool: Tool, base: dict[str, str]) -> Decision | None:
        if not tool.enabled:
            return Decision.deny(Reason.TOOL_DISABLED, message="tool is disabled", **base)
        if not tool.server.enabled:
            return Decision.deny(Reason.SERVER_DISABLED, message="server is disabled", **base)
        return None

    def _resolve_principals(
        self, db: DbSession, ctx: RequestContext, base: dict[str, str]
    ) -> tuple[ResolvedPrincipals, Decision | None]:
        principals = ResolvedPrincipals()
        if ctx.user_id:
            user = get_user(db, ctx.user_id)
            if user is None:
                return principals, Decision.deny(
                    Reason.UNAUTHENTICATED, message=f"unknown user {ctx.user_id}", **base
                )
            if not user.is_active:
                return principals, Decision.deny(
                    Reason.IDENTITY_DISABLED, message=f"user {user.id} is disabled", **base
                )
            principals.user = user
            principals.user_permissions = permissions_for_user(db, user)

        if ctx.service_account_id and not ctx.user_id and not ctx.agent_id:
            # A service account presenting its own credential is its own
            # principal: there is no identity to borrow, so no grant is needed.
            sa = resolve_service_account(db, ctx.service_account_id)
            if sa is None or not sa.is_active:
                return principals, Decision.deny(
                    Reason.IDENTITY_DISABLED,
                    message=f"unknown or disabled service account {ctx.service_account_id}",
                    **base,
                )
            principals.service_account = sa
            principals.service_account_permissions = permissions_for_service_account(db, sa)

        if ctx.agent_id:
            agent = get_agent(db, ctx.agent_id)
            if agent is None:
                return principals, Decision.deny(
                    Reason.UNAUTHENTICATED, message=f"unknown agent {ctx.agent_id}", **base
                )
            if not agent.is_active:
                return principals, Decision.deny(
                    Reason.IDENTITY_DISABLED, message=f"agent {agent.name} is disabled", **base
                )
            principals.agent = agent
            principals.agent_permissions = permissions_for_agent(db, agent)

        return principals, None

    @staticmethod
    def _check_persona(
        ctx: RequestContext, principals: ResolvedPrincipals, base: dict[str, str]
    ) -> Decision | None:
        if ctx.persona == Persona.NON_USER and ctx.user_id is not None:
            return Decision.deny(
                Reason.PERSONA_VIOLATION,
                message="a non-user persona cannot carry a human user identity",
                **base,
            )
        if ctx.persona == Persona.USER and ctx.user_id is None:
            return Decision.deny(
                Reason.PERSONA_VIOLATION,
                message="user persona requires a user identity",
                **base,
            )
        agent = principals.agent
        if agent is not None and agent.kind == AgentKind.AUTONOMOUS and ctx.user_id is not None:
            return Decision.deny(
                Reason.PERSONA_VIOLATION,
                message=f"autonomous agent {agent.name} cannot act as user {ctx.user_id}",
                details={"agent": agent.name},
                **base,
            )
        return None

    def _resolve_execution_identity(
        self,
        db: DbSession,
        ctx: RequestContext,
        tool: Tool,
        principals: ResolvedPrincipals,
        *,
        requested_service_account: str | None,
        base: dict[str, str],
    ) -> Decision:
        identifier = requested_service_account or tool.default_service_account_id
        needs_sa = tool.requires_service_account or requested_service_account is not None

        if not needs_sa:
            execution_identity = (
                principals.user.id if principals.user else principals.agent.id  # type: ignore[union-attr]
            )
            return Decision.allow(
                policy=_policy_name(principals.user_permissions or principals.agent_permissions),
                execution_identity=execution_identity,
                **base,
            )

        if not identifier:
            return Decision.deny(
                Reason.SERVICE_ACCOUNT_REQUIRED,
                message=f"{tool.qualified_name} must run under a service account",
                **base,
            )

        sa = resolve_service_account(db, identifier)
        if sa is None or not sa.is_active:
            return Decision.deny(
                Reason.SERVICE_ACCOUNT_NOT_AUTHORIZED,
                message=f"unknown or disabled service account: {identifier}",
                **base,
            )

        grantee_type, grantee_id = _grantee_for(ctx)
        if grantee_id is None:  # pragma: no cover - guarded by _check_identity
            return Decision.deny(Reason.UNAUTHENTICATED, message="no principal", **base)

        if not may_use_service_account(
            db, grantee_type=grantee_type, grantee_id=grantee_id, service_account_id=sa.id
        ):
            return Decision.deny(
                Reason.SERVICE_ACCOUNT_NOT_AUTHORIZED,
                message=f"{grantee_id} is not authorized to use service account {sa.name}",
                service_account_id=sa.id,
                details={"service_account": sa.name, "grantee": grantee_type.value},
                **base,
            )

        # The service account must itself be permitted to run the tool: a grant
        # lets you borrow an identity, it does not widen what that identity can do.
        sa_permissions = permissions_for_service_account(db, sa)
        if not sa_permissions.permits(tool.permission):
            return Decision.deny(
                Reason.SERVICE_ACCOUNT_NOT_PERMITTED,
                policy=_policy_name(sa_permissions),
                message=f"service account {sa.name} lacks {tool.permission}",
                service_account_id=sa.id,
                details={"service_account": sa.name},
                **base,
            )

        principals.service_account = sa
        principals.service_account_permissions = sa_permissions
        return Decision.allow(
            policy=_policy_name(principals.user_permissions or principals.agent_permissions),
            execution_identity=sa.id,
            service_account_id=sa.id,
            details={"service_account": sa.name},
            **base,
        )


def _grantee_for(ctx: RequestContext) -> tuple[IdentityType, str | None]:
    """Who is borrowing the service account.

    For a user-driven call it is the human — the agent cannot escalate by
    holding a grant the user does not have. For an autonomous call it is the
    agent itself.
    """
    if ctx.user_id:
        return IdentityType.USER, ctx.user_id
    return IdentityType.AGENT, ctx.agent_id


def _policy_name(pset: PermissionSet) -> str | None:
    return ", ".join(pset.sources) if pset.sources else None
