"""Example Kubernetes MCP server."""

from .server import AUDIENCE, PROTECTED_NAMESPACES, TOOLS, create_app

__all__ = ["AUDIENCE", "PROTECTED_NAMESPACES", "TOOLS", "create_app"]
