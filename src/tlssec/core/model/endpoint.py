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
    last_seen: datetime = None
    retire_at: datetime | None = None

    @model_validator(mode = 'after')
    def default_now(self):
        # Ensure defaulting to now get the exact same value across multiple fields
        now = datetime.now()
        if self.first_seen is None:
            self.first_seen = now
        if self.last_seen is None:
            self.last_seen = now
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
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone = True))
    retire_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone = True),
        nullable = True,
    )

    service: Mapped[Optional['ServiceTable']] = relationship(back_populates = 'endpoints')
    scans: Mapped[list['ScanTable']] = relationship(back_populates = 'endpoint')

class Tag(BaseModel):
    """Tags to help organize and search for services."""
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    parent_id: int | None = None
    name: str = PydanticField(
        min_length=1,
        max_length=30,
        pattern=r'^[a-zA-Z_][a-zA-Z0-9_]*$',
    )
    description: EmptyToNoneStr = None


class TagTable(Base):
    id: Mapped[int] = mapped_column(Integer, Identity(always=True), primary_key=True)
    parent_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey('service_tag.id', ondelete='SET NULL'),
        nullable=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(30), index=True)
    description: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            'parent_id', 'name',
            postgresql_nulls_not_distinct=True,
        ),
    )

    parent: Mapped[Optional['ServiceTagTable']] = relationship(
        back_populates='children',
        foreign_keys='[ServiceTagTable.parent_id]',
        remote_side='ServiceTagTable.id',
    )
    children: Mapped[dict[str, 'ServiceTagTable']] = relationship(
        back_populates='parent',
        foreign_keys='[ServiceTagTable.parent_id]',
        collection_class=attribute_keyed_dict('name'),
    )
    services: Mapped[list['ServiceTable']] = relationship(
        secondary='service_tag_map',
        back_populates='tags',
    )

    def __init__(self, children=None, **kwargs):
        if isinstance(children, list):
            children = {child.name: child for child in children}
        if children:
            kwargs['children'] = children
        super().__init__(**kwargs)

    @property
    def fullpath(self) -> PurePosixPath:
        cursor = self
        lineage = []
        visited = set()
        while cursor is not None:
            if id(cursor) in visited:
                raise ValueError(f'tag loop detected: {lineage}')
            lineage.append(cursor)
            visited.add(id(cursor))
            cursor = cursor.parent
        return PurePosixPath(
            '/',
            *(tag.name for tag in reversed(lineage)),
        )


class ServiceTagMap(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    endpoint_id: int
    tag_id: int


class ServiceTagMapTable(Base):
    endpoint_id: Mapped[int] = mapped_column(ForeignKey('service.id'), primary_key=True)
    tag_id: Mapped[int] = mapped_column(ForeignKey('service_tag.id'), primary_key=True, index=True)

