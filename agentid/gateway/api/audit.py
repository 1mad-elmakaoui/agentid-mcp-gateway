"""Audit query API."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query

from ...audit.storage import event_to_dict, query_events
from ..deps import AdminDep, ContextDep, DbDep

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/events")
def list_events(
    _admin: AdminDep,
    db: DbDep,
    user_id: str | None = None,
    agent_id: str | None = None,
    tool: str | None = None,
    server: str | None = None,
    decision: str | None = None,
    action: str | None = None,
    request_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, object]:
    events = query_events(
        db,
        user_id=user_id,
        agent_id=agent_id,
        tool=tool,
        server=server,
        decision=decision,
        action=action,
        request_id=request_id,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )
    return {"count": len(events), "events": [event_to_dict(e) for e in events]}


@router.get("/me")
def my_events(
    ctx: ContextDep,
    db: DbDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> dict[str, object]:
    """A caller can always read their own trail, without admin rights."""
    events = query_events(
        db,
        user_id=ctx.user_id,
        agent_id=None if ctx.user_id else ctx.agent_id,
        limit=limit,
    )
    return {"count": len(events), "events": [event_to_dict(e) for e in events]}
