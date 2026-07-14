from pathlib import Path
from datetime import datetime
from enum import StrEnum, auto
from typing import Optional

from pydantic import BaseModel, ConfigDict, IPvAnyAddress
from sqlalchemy import Integer, Identity, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
import yaml

from tlssec.database.base import Base
from tlssec.database.types import InetType


class Scanner(StrEnum):
    """Which external tool produced a raw scan.

    Stored on every raw scan so the CBOM builder knows how to parse ``result``
    and so scans can be dispatched/filtered by tool.
    """
    testssl = auto()
    ssh_audit = auto()


class Scan(BaseModel):
    """A record about a single execution of scan."""
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    result: dict | list
    scanner: Scanner = Scanner.testssl
    scanner_version: str | None = None
    # The IP the scanner actually connected to, and the server name (SNI) it
    # sent. observed_ip can differ from the endpoint's own IP behind a load
    # balancer / round-robin DNS, so it is recorded per scan rather than assumed
    # equal to the endpoint. sni is None for protocols without SNI (e.g. SSH).
    observed_ip: IPvAnyAddress | None = None
    sni: str | None = None
    start_time: datetime | None = None
    time_taken: int | None = None
    belong_to_endpoint_id: int | None = None

    @classmethod
    def from_file(cls, path: Path):
        try:
            with path.open() as f:
                content = yaml.safe_load(f)
        except Exception as e:
            raise ValueError(f'Can not load scanning record from {path}') from e

        # TODO: Try getting start_time from content,
        # or use mtime of input file
        return cls.model_validate({
            'result': content,
        })


class ScanTable(Base):
    id: Mapped[int] = mapped_column(Integer, Identity(always=True), primary_key=True)
    result: Mapped[dict | list] = mapped_column(JSONB)
    scanner: Mapped[Scanner] = mapped_column(default=Scanner.testssl)
    scanner_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    observed_ip: Mapped[Optional[str]] = mapped_column(InetType, nullable=True)
    sni: Mapped[Optional[str]] = mapped_column(String(253), nullable=True)
    start_time: Mapped[Optional[datetime]] = mapped_column(nullable=True, index=True)
    time_taken: Mapped[Optional[int]] = mapped_column(nullable=True)
    belong_to_endpoint_id: Mapped[Optional[int]] = mapped_column(ForeignKey('endpoint.id'), index=True)

    endpoint: Mapped[Optional['EndpointTable']] = relationship(back_populates='scans')
    # 1:1 materialized CBOM built from this raw scan (see tlssec.core.cbom).
    cbom: Mapped[Optional['CbomTable']] = relationship(
        back_populates='scan',
        uselist=False,
        cascade='all, delete-orphan',
    )
