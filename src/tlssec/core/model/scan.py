from pathlib import Path
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict
from sqlalchemy import Integer, Identity, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
import yaml

from tlssec.database.base import Base


class Scan(BaseModel):
    """A record about a single execution of scan."""
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    result: dict | list
    start_time: datetime | None = None
    time_taken: int | None = None
    belong_to_endpoint_id: int

    @classmethod
    def from_file(cls, path: Path):
        try:
            with path.open() as f:
                content = yaml.safe_load(f)
        except Exception as e:
            raise ValueError(f'Can not load scanning record from {path}') from e
        return cls.model_validate({
            'result': content,
            'belong_to_endpoint_id': 0,  # placeholder; caller must set
        })


class ScanTable(Base):
    id: Mapped[int] = mapped_column(Integer, Identity(always=True), primary_key=True)
    result: Mapped[dict | list] = mapped_column(JSONB)
    start_time: Mapped[Optional[datetime]] = mapped_column(nullable=True, index=True)
    time_taken: Mapped[Optional[int]] = mapped_column(nullable=True)
    belong_to_endpoint_id: Mapped[int] = mapped_column(ForeignKey('endpoint.id'), index=True)

    endpoint: Mapped[Optional['EndpointTable']] = relationship(back_populates='scans')
