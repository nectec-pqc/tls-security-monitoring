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
    service_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("service.id"),
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
    service: Mapped[Optional["Service"]] = relationship(
        "Service",
        back_populates="endpoints",
    )
    scans: Mapped[list["Scan"]] = relationship(
        "Scan",
        back_populates="endpoint",
    )

    __table_args__ = (
        UniqueConstraint("service_id", "hostname", "port", "protocol"),
    )
