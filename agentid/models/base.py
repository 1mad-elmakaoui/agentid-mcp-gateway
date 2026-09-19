"""Declarative base, id generation and shared mixins."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Generic, TypeVar

from sqlalchemy import DateTime, MetaData, String, TypeDecorator
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

E = TypeVar("E", bound=Enum)

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    """Generate a readable, prefixed identifier such as ``user_9f2c1a...``."""
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


def as_aware(value: datetime | None) -> datetime | None:
    """SQLite drops tzinfo; normalise everything back to UTC-aware."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class EnumType(TypeDecorator, Generic[E]):
    """Store a ``str``-valued Enum as text and read it back as the Enum.

    A plain ``String`` column round-trips to ``str``, which quietly breaks
    ``event.persona.value`` and any ``isinstance`` check downstream.
    """

    impl = String
    cache_ok = True

    def __init__(self, enum_cls: type[E], length: int = 32, **kwargs: Any) -> None:
        self.enum_cls = enum_cls
        super().__init__(length, **kwargs)

    def process_bind_param(self, value: Any, _dialect: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, Enum):
            return str(value.value)
        return str(self.enum_cls(value).value)

    def process_result_value(self, value: Any, _dialect: Any) -> E | None:
        if value is None:
            return None
        return self.enum_cls(value)
