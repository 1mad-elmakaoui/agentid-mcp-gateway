"""Example GitHub MCP server.

Verifies the gateway credential, then applies its own repository-level rules.
The in-memory store keeps the demo self-contained.
"""

from __future__ import annotations

import itertools
from typing import Any

from fastapi import FastAPI

from ...sdk.server import GatewayClaims
from ..common import ResourceDenied, ToolSpec, build_server, text

AUDIENCE = "agentid-mcp:github"

#: repo -> identities allowed to write to it. Resource authorization lives here,
#: not in the gateway.
WRITABLE_REPOS: dict[str, set[str]] = {}

_issues: dict[int, dict[str, Any]] = {}
_issue_ids = itertools.count(1)

_REPOS = {
    "company/backend": {"private": True, "description": "Backend services"},
    "company/frontend": {"private": True, "description": "Web client"},
    "company/docs": {"private": False, "description": "Public documentation"},
}


def reset_state() -> None:
    """Used by tests and the demo to start from a clean slate."""
    global _issue_ids
    _issues.clear()
    _issue_ids = itertools.count(1)
    WRITABLE_REPOS.clear()


def allow_write(repo: str, *identities: str) -> None:
    WRITABLE_REPOS.setdefault(repo, set()).update(identities)


def _require_repo(repo: str) -> dict[str, Any]:
    if repo not in _REPOS:
        raise ResourceDenied(f"unknown repository: {repo}", resource=repo)
    return _REPOS[repo]


def _require_write(claims: GatewayClaims, repo: str) -> None:
    _require_repo(repo)
    allowed = WRITABLE_REPOS.get(repo, set())
    # Any identity in the chain may carry the repository grant: the human, the
    # acting agent, or the service account the call executes as.
    chain = {claims.subject, claims.agent, claims.on_behalf_of, claims.service_account}
    if not (chain & allowed):
        raise ResourceDenied(
            f"{claims.identity_chain()} may not write to {repo}", resource=repo
        )


def _create_issue(claims: GatewayClaims, arguments: dict[str, Any]) -> dict[str, Any]:
    repo = str(arguments.get("repo", ""))
    title = str(arguments.get("title", "")).strip()
    if not repo or not title:
        return text("repo and title are required", is_error=True)
    _require_write(claims, repo)
    number = next(_issue_ids)
    _issues[number] = {
        "number": number,
        "repo": repo,
        "title": title,
        "body": arguments.get("body", ""),
        "created_by": claims.identity_chain(),
        "state": "open",
    }
    return text(f"Created issue #{number} in {repo}: {title}")


def _get_issue(claims: GatewayClaims, arguments: dict[str, Any]) -> dict[str, Any]:
    number = int(arguments.get("number", 0))
    issue = _issues.get(number)
    if issue is None:
        return text(f"issue #{number} not found", is_error=True)
    _require_repo(issue["repo"])
    return text(
        f"#{issue['number']} [{issue['state']}] {issue['repo']}: {issue['title']} "
        f"(opened by {issue['created_by']})"
    )


def _search_repository(_claims: GatewayClaims, arguments: dict[str, Any]) -> dict[str, Any]:
    query = str(arguments.get("query", "")).lower()
    hits = [
        name
        for name, meta in _REPOS.items()
        if query in name.lower() or query in str(meta["description"]).lower()
    ]
    return text("\n".join(hits) if hits else "no repositories matched")


def _list_issues(_claims: GatewayClaims, arguments: dict[str, Any]) -> dict[str, Any]:
    repo = arguments.get("repo")
    rows = [i for i in _issues.values() if repo is None or i["repo"] == repo]
    if not rows:
        return text("no issues")
    return text("\n".join(f"#{i['number']} {i['repo']}: {i['title']}" for i in rows))


TOOLS = [
    ToolSpec(
        name="create_issue",
        description="Create an issue in a repository",
        input_schema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "title": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["repo", "title"],
        },
        handler=_create_issue,
    ),
    ToolSpec(
        name="get_issue",
        description="Read a single issue by number",
        input_schema={
            "type": "object",
            "properties": {"number": {"type": "integer"}},
            "required": ["number"],
        },
        handler=_get_issue,
    ),
    ToolSpec(
        name="list_issues",
        description="List issues, optionally filtered by repository",
        input_schema={"type": "object", "properties": {"repo": {"type": "string"}}},
        handler=_list_issues,
    ),
    ToolSpec(
        name="search_repository",
        description="Search repositories by name or description",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
        handler=_search_repository,
    ),
]


def create_app(secret: str | None = None) -> FastAPI:
    return build_server(
        title="GitHub MCP", audience=AUDIENCE, tools=TOOLS, secret=secret
    )


app = create_app()
