"""Example PostgreSQL MCP server."""

from .server import AUDIENCE, RESTRICTED_TABLES, TOOLS, create_app

__all__ = ["AUDIENCE", "RESTRICTED_TABLES", "TOOLS", "create_app"]
