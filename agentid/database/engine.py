"""Engine and session management.

SQLite is the default so the gateway runs with no external dependencies;
``AGENTID_DATABASE_URL`` switches it to PostgreSQL for anything real.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from ..config import Settings, get_settings
from ..models import Base

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def _engine_kwargs(url: str) -> dict[str, object]:
    if url.startswith("sqlite"):
        kwargs: dict[str, object] = {"connect_args": {"check_same_thread": False}}
        if ":memory:" in url:
            # Keep one connection alive so an in-memory DB survives between
            # sessions (used heavily by the test suite).
            kwargs["poolclass"] = StaticPool
        return kwargs
    return {"pool_pre_ping": True}


def create_db_engine(url: str | None = None, *, settings: Settings | None = None) -> Engine:
    settings = settings or get_settings()
    url = url or settings.database_url
    engine = create_engine(url, echo=settings.debug, future=True, **_engine_kwargs(url))
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, _record):  # pragma: no cover - driver glue
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = create_db_engine()
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(
            bind=get_engine(), expire_on_commit=False, autoflush=False, future=True
        )
    return _session_factory


def configure(engine: Engine) -> None:
    """Point the process at a specific engine (used by tests and the CLI)."""
    global _engine, _session_factory
    _engine = engine
    _session_factory = sessionmaker(
        bind=engine, expire_on_commit=False, autoflush=False, future=True
    )


def reset() -> None:
    global _engine, _session_factory
    _engine = None
    _session_factory = None


def create_all(engine: Engine | None = None) -> None:
    Base.metadata.create_all(engine or get_engine())


def drop_all(engine: Engine | None = None) -> None:
    Base.metadata.drop_all(engine or get_engine())


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope around a series of operations."""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def db_session() -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()
