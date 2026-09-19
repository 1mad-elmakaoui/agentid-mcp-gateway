"""The security lifecycle of a single MCP invocation.

    Authenticate -> Resolve identity -> Determine persona -> Authorize
    -> Resolve credential -> Route MCP request -> Audit

Authentication and identity resolution happen in the auth dependency; this
service owns everything from authorization onwards. Every exit path — allowed,
denied, or failed downstream — writes exactly one audit event.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session as DbSession

from ...audit.events import Action, Outcome
from ...audit.logger import AuditLogger
from ...authorization.decisions import Decision
from ...authorization.engine import AuthorizationEngine
from ...config import Settings, get_settings
from ...context import RequestContext
from ...credentials.manager import CredentialManager
from ...errors import AgentIDError, AuthorizationError, DownstreamError
from ..mcp.discovery import DiscoveryResult, discover
from ..mcp.proxy import McpProxy, ProxyResponse
from ..mcp.router import Route, resolve_route


@dataclass(slots=True)
class CallOutcome:
    decision: Decision
    route: Route | None = None
    response: ProxyResponse | None = None
    latency_ms: int = 0
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision.allowed


class McpService:
    def __init__(
        self,
        *,
        engine: AuthorizationEngine,
        credentials: CredentialManager,
        proxy: McpProxy,
        audit: AuditLogger,
        settings: Settings | None = None,
    ) -> None:
        self.engine = engine
        self.credentials = credentials
        self.proxy = proxy
        self.audit = audit
        self.settings = settings or get_settings()

    # -- discovery -------------------------------------------------------
    def discover_tools(
        self,
        db: DbSession,
        ctx: RequestContext,
        *,
        query: str = "",
        servers: list[str] | None = None,
        limit: int = 20,
    ) -> DiscoveryResult:
        result = discover(db, ctx, engine=self.engine, query=query, servers=servers, limit=limit)
        self.audit.log(
            db,
            ctx,
            action=Action.TOOL_DISCOVER,
            decision=Outcome.ALLOW,
            reason="allowed",
            details={
                "query": query,
                "returned": len(result.matches),
                "filtered_out": result.filtered_out,
            },
        )
        return result

    # -- invocation ------------------------------------------------------
    async def call_tool(
        self,
        db: DbSession,
        ctx: RequestContext,
        *,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        server_hint: str | None = None,
        service_account: str | None = None,
        resource: str | None = None,
    ) -> CallOutcome:
        started = time.perf_counter()
        arguments = arguments or {}

        # 1. Route (identity-independent) so the audit trail can name the tool
        #    even when authorization fails.
        try:
            route = resolve_route(db, tool_name, server_hint=server_hint)
        except AgentIDError as exc:
            ctx.with_tool(server=server_hint, tool=tool_name, resource=resource)
            self.audit.log(
                db,
                ctx,
                action=Action.TOOL_CALL,
                decision=Outcome.DENY,
                reason=exc.code,
                error=exc.message,
                status_code=exc.status_code,
                latency_ms=_elapsed_ms(started),
            )
            raise

        ctx.with_tool(server=route.server.name, tool=route.qualified_name, resource=resource)

        # 2. Authorize — always before routing the request onward.
        decision = self.engine.authorize_tool(
            db, ctx, route.tool, requested_service_account=service_account
        )
        if not decision.allowed:
            self.audit.log(
                db,
                ctx,
                action=Action.TOOL_CALL,
                decision=Outcome.DENY,
                reason=decision.reason.value,
                policy=decision.policy,
                status_code=403,
                latency_ms=_elapsed_ms(started),
                details=decision.to_dict(),
            )
            raise AuthorizationError(
                decision.message or "not authorized",
                code=decision.reason.value,
                tool=route.qualified_name,
                policy=decision.policy,
            )

        # The execution identity is only known once authorization succeeded.
        ctx.service_account_id = decision.service_account_id

        # 3. Resolve the downstream credential. The client never sees it.
        try:
            credential = self.credentials.resolve(db, ctx, route.server)
        except AgentIDError as exc:
            self.audit.log(
                db,
                ctx,
                action=Action.TOOL_CALL,
                decision=Outcome.ERROR,
                reason=exc.code,
                error=exc.message,
                status_code=exc.status_code,
                latency_ms=_elapsed_ms(started),
            )
            raise

        # 4. Forward.
        try:
            response = await self.proxy.call_tool(
                route, arguments, headers=credential.headers, request_id=ctx.request_id
            )
        except DownstreamError as exc:
            self.audit.log(
                db,
                ctx,
                action=Action.TOOL_CALL,
                decision=Outcome.ERROR,
                reason=exc.code,
                error=exc.message,
                status_code=exc.status_code,
                latency_ms=_elapsed_ms(started),
                policy=decision.policy,
                details=credential.audit_fields(),
            )
            raise

        latency = _elapsed_ms(started)
        outcome = Outcome.ERROR if response.is_error else Outcome.ALLOW

        # 5. Audit.
        self.audit.log(
            db,
            ctx,
            action=Action.TOOL_CALL,
            decision=outcome,
            reason=decision.reason.value if outcome == Outcome.ALLOW else "downstream_error",
            policy=decision.policy,
            status_code=response.status_code,
            latency_ms=latency,
            error=_downstream_error_message(response),
            details={
                **credential.audit_fields(),
                "arguments": _summarise_arguments(arguments),
            },
        )
        return CallOutcome(
            decision=decision, route=route, response=response, latency_ms=latency
        )


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _downstream_error_message(response: ProxyResponse) -> str | None:
    if response.error:
        return str(response.error.get("message", response.error))
    if response.result and response.result.get("isError"):
        content = response.result.get("content") or []
        if content and isinstance(content[0], dict):
            return str(content[0].get("text", "downstream reported an error"))
        return "downstream reported an error"
    return None


def _summarise_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Record argument *shape*, not values: arguments may carry user data."""
    return {"keys": sorted(arguments.keys()), "count": len(arguments)}
