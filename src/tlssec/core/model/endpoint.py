from datetime import datetime
from typing import Optional

from sqlalchemy import (
        Column,
        Integer,
        Identity,
        String,
        UniqueConstraint,
        ForeignKey,
        DateTime,
    )
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Relationship


class Base(DeclarativeBase):
    pass


class EndPoint(Base):

    __tablenmae__ = "end_point"

    id: Mapped[int] = mapped_column(
        Integer,
        Identity(always=True),
        primary_key=True,
    )
    target_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("target.id"),
        index=True,
        nullable=False,
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(50), default="tcp", nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    retired_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        index=True,
        default=None,
    )

    # Relationships
    target: Mapped[Optional["Target"]] = relationship(
        "Target",
        back_populates="endpoints",
    )
    scans: Mapped[list["Scan"]] = relationship(
        "Scan",
        back_populates="endpoint",
    )

    __table_args__ = (
        UniqueConstraint("target_id", "hostname", "port", "protocol"),
    )
