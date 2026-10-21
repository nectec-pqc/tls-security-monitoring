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
    Identity,
    Index,
    Integer,
    String,
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
from .validator import EmptyToNoneStr


class TlsMode(StrEnum):
    implicit = auto()
    explicit = auto()
    none = auto()


class Endpoint(BaseModel):
    model_config = ConfigDict(from_attributes = True)

    id: int | None = None
    ip: IPvAnyAddress | None = None
    hostname: EmptyToNoneStr = PydanticField(
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
    application_protocol: EmptyToNoneStr = PydanticField(
        default = 'https',
        examples = ['http', 'https', 'ftp', 'smtp', 'dns', 'postgres', 'mysql'],
        min_length = 1,
        max_length = 40,
    )
    service_info: EmptyToNoneStr = PydanticField(
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
    # TODO: rename to first_tracked or created_at
    first_seen: datetime | None = PydanticField(
        default = None,
        description = (
            'Marks when endpoint first get tracked in database.'
            ' Python side defaults to None, DB server defaults to now.'
        ),
    )
    # TODO: rename to last_scanned? ... or even remove entirely as it can be inferred by joining with ScanTable.
    # However, storing last_scanned time directly could make some query faster.
    last_seen: datetime | None = PydanticField(
        default = None,
        description = (
            'The last scan time. Stays None until the first recorded scan.'
            ' Newly tracked endpoint set last_seen to None to indicate it was never scanned.'
            ' Will be checked against cooldown time if the endpoint is due to be re-scanned.'
        ),
    )
    retire_at: datetime | None = None

    @model_validator(mode = 'after')
    def check_at_least_ip_or_hostname_is_specified(self):
        if self.ip is None and self.hostname is None:
            raise ValueError('Endpoint must specify at least IP or hostname')
        return self


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
    tls_mode: Mapped[Optional[TlsMode]] = mapped_column(
        default = None,
    )
    first_seen: Mapped[datetime] = mapped_column(
        server_default = func.now(),
    )
    # Nullable: unset until the first recorded scan (the cooldown clock).
    last_seen: Mapped[Optional[datetime]]
    retire_at: Mapped[Optional[datetime]]

    tags: Mapped[set['TagTable']] = relationship(
        secondary = 'endpoint_tag_map',
        back_populates = 'endpoints',
    )
    scans: Mapped[list['ScanTable']] = relationship(
        back_populates = 'endpoint',
    )


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
