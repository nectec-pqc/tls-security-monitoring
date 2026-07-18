from datetime import datetime
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
    first_seen: datetime = None
    # last_seen is the last *scan* time (the cooldown clock). It stays None until
    # the first recorded scan, so a newly tracked endpoint reads as never-scanned.
    last_seen: datetime | None = None
    retire_at: datetime | None = None

    @model_validator(mode = 'after')
    def default_first_seen(self):
        # first_seen marks when tracking began, so default it to now. last_seen is
        # intentionally NOT defaulted: leaving it None keeps a fresh endpoint "due"
        # (never scanned) instead of looking just-scanned to the cooldown filter.
        if self.first_seen is None:
            self.first_seen = datetime.now()
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
