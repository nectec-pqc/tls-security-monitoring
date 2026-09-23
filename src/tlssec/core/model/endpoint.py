from datetime import datetime, UTC
from typing import Optional
from enum import StrEnum, auto

from pydantic import (
    BaseModel,
    IPvAnyAddress,
    ConfigDict,
    Field as PydanticField,
    model_validator,
)
from sqlalchemy import (
    Integer,
    Identity,
    String,
    DateTime,
    Index,
    func,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from tlssec.database.base import Base
from tlssec.database.types import InetType
from tlssec.core.model.validator import UrlPath


class TlsMode(StrEnum):
    implicit = auto()
    explicit = auto()
    none = auto()


class Endpoint(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    ip: IPvAnyAddress | None = None
    hostname: str | None = PydanticField(
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
    application_protocol: str | None = PydanticField(
        default = 'https',
        examples = ['http', 'https', 'ftp', 'smtp', 'dns', 'postgres', 'mysql'],
        min_length = 1,
        max_length = 40,
    )
    service_info: str | None = PydanticField(
        default = None,
        min_length = 1,
        max_length = 100,
    )
    tls_mode: TlsMode | None = PydanticField(
        default = None,
        description = (
            'None means TLS mode of operation is unknown.'
            ' String "none" means there is no TLS.'
        ),
    )
    first_seen: datetime = PydanticField(
        default_factory = lambda: datetime.now(UTC),
        description = (
            'Marks when endpoint first get tracked in system, so it defaults to now'
        ),
    )
    last_seen: datetime | None = PydanticField(
        default = None,
        description = (
            'The last scan time. Stays None until the first recorded scan.'
            ' Newly tracked endpoint set last_seen to None to indicate it was never scanned.'
            ' Will be checked against cooldown time if the endpoint is due to be re-scanned.'
        ),
    )
    retire_at: datetime | None = None


class EndpointTable(Base):
    id: Mapped[int] = mapped_column(
        Integer,
        Identity(always = True),
        primary_key = True,
    )
    ip: Mapped[Optional[str]] = mapped_column(
        InetType,
        nullable = True,
    )
    hostname: Mapped[Optional[str]] = mapped_column(String(253))
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
    application_protocol: Mapped[Optional[str]] = mapped_column(
        String(40),
        default = 'https',
    )
    service_info: Mapped[Optional[str]] = mapped_column(
        String(100),
        default = None,
    )
    tls_mode: Mapped[TlsMode] = mapped_column(
        nullable = True,
        default = None,
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone = True))
    # Nullable: unset until the first recorded scan (the cooldown clock).
    last_seen: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone = True),
        nullable = True,
    )
    retire_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone = True),
        nullable = True,
    )

    tags: Mapped[list['TagTable']] = relationship(
        secondary='endpoint_tag_map',
        back_populates='endpoints',
    )
    scans: Mapped[list['ScanTable']] = relationship(back_populates='endpoint')


# Scan identity: an endpoint is uniquely (hostname-or-ip, port, transport). This
# is the same key nmap discovery de-dup uses (endpoint_identity_key) and exactly
# what determines the scan target -- path / application_protocol are intentionally
# excluded. host(ip) drops any netmask; COALESCE prefers the hostname over the ip.
Index(
    'uq_endpoint_identity',
    func.coalesce(EndpointTable.hostname, func.host(EndpointTable.ip)),
    EndpointTable.port,
    EndpointTable.transport_protocol,
    unique = True,
)
