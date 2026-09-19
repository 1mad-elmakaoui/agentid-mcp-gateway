"""MCP server registry and tool catalog."""

from .schemas import ServerRegistration, ServerSchema, ToolRegistration, ToolSchema
from .servers import (
    delete_server,
    get_server_by_name,
    list_servers,
    register_server,
    require_server,
    resolve_server,
    set_enabled,
    update_server,
)
from .tools import (
    ToolMatch,
    delete_tool,
    get_tool,
    list_tools,
    register_tool,
    require_tool,
    score_tool,
    search_tools,
)

__all__ = [
    "ServerRegistration",
    "ServerSchema",
    "ToolMatch",
    "ToolRegistration",
    "ToolSchema",
    "delete_server",
    "delete_tool",
    "get_server_by_name",
    "get_tool",
    "list_servers",
    "list_tools",
    "register_server",
    "register_tool",
    "require_server",
    "require_tool",
    "resolve_server",
    "score_tool",
    "search_tools",
    "set_enabled",
    "update_server",
]
