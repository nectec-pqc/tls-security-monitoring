from datetime import datetime
from typing import Optional
from enum import Enum, auto

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


class TlsMode(str, Enum):
    implicit = auto()
    explicit = auto()
    none = auto()


class Endpoint(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    part_of_service_id: int
    ip: IPvAnyAddress | None = None
    hostname: str = PydanticField(
        min_length = 1,
        max_length = 253,
    )
    port: int = PydanticField(
        default = 443,
        ge = 1,
        le = 65535,
    )
    path: UrlPath = '/'
    # NOTE: Protocols are stored with string, not enum to allow flexibility of
    # storing unrecognized protocol first then classifying them later.
    transport_protocol: str = PydanticField(
        default = 'tcp',
        examples = ['udp', 'tcp'],
        min_length = 1,
        max_length = 10,
    )
    application_protocol: str = PydanticField(
        default = 'https',
        examples = ['http', 'https', 'ftp', 'smtp', 'dns', 'postgres', 'mysql'],
        min_length = 1,
        max_length = 10,
    )
    tls_mode: TlsMode | None = PydanticField(
        default = None,
        description = (
            'None means TLS mode of operation is unknown.'
            ' String "none" means there is no TLS.'
        ),
    )
    first_seen: datetime
    last_seen: datetime
    retire_at: datetime | None = None


class EndpointTable(Base):
    id: Mapped[int] = mapped_column(
        Integer,
        Identity(always = True),
        primary_key = True,
    )
    part_of_service_id: Mapped[int] = mapped_column(
        ForeignKey('service.id'),
        index = True,
    )
    ip: Mapped[Optional[str]] = mapped_column(
        InetType,
        nullable = True,
    )
    hostname: Mapped[str] = mapped_column(String(253))
    port: Mapped[int] = mapped_column(
        Integer,
        default = 443,
    )
    path: Mapped[str] = mapped_column(
        String,
        default = '/',
    )
    transport_protocol: Mapped[str] = mapped_column(
        String(10),
        default = 'tcp',
    )
    application_protocol: Mapped[str] = mapped_column(
        String(10),
        default = 'https',
    )
    tls_mode: Mapped[TlsMode] = mapped_column(
        nullable = True,
        default = None,
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone = True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone = True))
    retire_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone = True),
        nullable = True,
    )

    service: Mapped[Optional['ServiceTable']] = relationship(back_populates = 'endpoints')
    scans: Mapped[list['ScanTable']] = relationship(back_populates = 'endpoint')
