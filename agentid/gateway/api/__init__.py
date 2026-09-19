"""Gateway HTTP API routers."""

from . import audit, auth, identity, mcp, policy, registry

ROUTERS = (auth.router, identity.router, policy.router, registry.router, mcp.router, audit.router)

__all__ = ["ROUTERS", "audit", "auth", "identity", "mcp", "policy", "registry"]
