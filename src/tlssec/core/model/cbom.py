from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict
from sqlalchemy import Integer, Identity, ForeignKey, String, DateTime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from tlssec.database.base import Base


class Cbom(BaseModel):
    """A CycloneDX 1.6 CBOM built from a single raw scan.

    This is Layer 2 (normalized facts): a vendor-neutral cryptographic
    inventory derived from the raw scanner output. It is a pure function of the
    raw scan, so it can always be rebuilt; ``builder_version`` records which
    builder produced it, which is what makes "rebuild only what is stale"
    correct.
    """
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    scan_id: int | None = None
    builder_version: str
    document: dict
    created_at: datetime | None = None


class CbomTable(Base):
    id: Mapped[int] = mapped_column(Integer, Identity(always=True), primary_key=True)
    # 1:1 with the raw scan it was built from.
    scan_id: Mapped[int] = mapped_column(
        ForeignKey('scan.id'),
        unique=True,
        index=True,
    )
    builder_version: Mapped[str] = mapped_column(String(50))
    document: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.now,
    )

    scan: Mapped['ScanTable'] = relationship(back_populates='cbom')
    # Derived opinions are kept as history (versioned by ruleset), newest wins.
    opinions: Mapped[list['OpinionTable']] = relationship(
        back_populates='cbom',
        cascade='all, delete-orphan',
    )
