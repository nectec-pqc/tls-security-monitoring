from datetime import datetime

from pydantic import BaseModel, ConfigDict
from sqlalchemy import Integer, Identity, ForeignKey, String, DateTime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from tlssec.database.base import Base


class Opinion(BaseModel):
    """A verdict derived from a CBOM (Layer 3: judgment).

    Opinions are re-derivable from the CBOM facts and change over time as
    standards evolve (new NIST guidance, PQC deadlines, new attacks), so they
    are kept separate from the CBOM and versioned by ``ruleset_version``. The
    ``verdict`` payload carries both our own assessment (e.g. quantum-safety,
    weak protocol/cipher) and captured vendor verdicts (testssl rating /
    vulnerabilities, ssh-audit notes / cves / recommendations).
    """
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    cbom_id: int | None = None
    ruleset_version: str
    verdict: dict | list
    created_at: datetime | None = None


class OpinionTable(Base):
    id: Mapped[int] = mapped_column(Integer, Identity(always=True), primary_key=True)
    cbom_id: Mapped[int] = mapped_column(ForeignKey('cbom.id'), index=True)
    ruleset_version: Mapped[str] = mapped_column(String(50))
    verdict: Mapped[dict | list] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.now,
    )

    cbom: Mapped['CbomTable'] = relationship(back_populates='opinions')
