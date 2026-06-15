from datetime import datetime
from typing import Optional
from enum import Enum

from pydantic import (
    BaseModel,
    IPvAnyAddress,
    ConfigDict,
    Field as PydanticField,
)
from sqlalchemy import (
    Integer,
    Identity,
    UniqueConstraint,
    String,
    ForeignKey,
    DateTime,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from tlssec.database.base import Base
from tlssec.database.types import InetType
from tlssec.core.model.validator import UrlPath


class Protocol(str, Enum):
    tcp = 'tcp'
    udp = 'udp'
    http = 'http'
    https = 'https'


class Endpoint(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    part_of_service_id: int
    ip: IPvAnyAddress | None = None
    hostname: str = PydanticField(min_length=1, max_length=253)
    port: int = PydanticField(default=443, ge=1, le=65535)
    path: UrlPath = '/'
    protocol: Protocol = Protocol.https
    first_seen: datetime
    last_seen: datetime
    retire_at: datetime | None = None


class EndpointTable(Base):
    id: Mapped[int] = mapped_column(Integer, Identity(always=True), primary_key=True)
    part_of_service_id: Mapped[int] = mapped_column(ForeignKey('service.id'), index=True)
    ip: Mapped[Optional[str]] = mapped_column(InetType, nullable=True)
    hostname: Mapped[str] = mapped_column(String(253))
    port: Mapped[int] = mapped_column(Integer, default=443)
    path: Mapped[str] = mapped_column(String, default='/')
    protocol: Mapped[Protocol] = mapped_column(
        default = Protocol.https,
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    retire_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint('part_of_service_id', 'hostname', 'port', 'protocol', 'path'),
    )

    service: Mapped[Optional['ServiceTable']] = relationship(back_populates='endpoints')
    scans: Mapped[list['ScanTable']] = relationship(back_populates='endpoint')
