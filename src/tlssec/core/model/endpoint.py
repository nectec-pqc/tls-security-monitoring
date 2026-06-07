from datetime import datetime
from typing import Optional, Literal
from enum import Enum

from sqlmodel import Field, Relationship
from sqlalchemy import Column, Integer, Identity, UniqueConstraint, String
from sqlalchemy.dialects.postgresql import INET
from pydantic import IPvAnyAddress
from pydantic import model_validator

from tlssec.database.sqlmodel import SQLModel  


class Protocol(str, Enum):
    tcp = 'tcp'
    udp = 'udp'
    http = 'http'
    https = 'https'


class Endpoint(SQLModel):
    id: int | None = Field(
        default = None,
        sa_column = Column(Integer, Identity(always = True), primary_key = True),
    )
    part_of_service_id: int = Field(
        foreign_key = 'service.id', 
        index = True,
    )
    ip: IPvAnyAddress = Field(
        default = None,
        # TODO: register custom mapping globally
        sa_type = INET,
    )

    hostname: str = Field(
        min_length = 1,
        max_length = 253,
    )
    port: int = Field(
        default = 443,
        ge = 1,
        le = 65535,
    )
    # TODO: Could we use a specialize path type?
    path: str = Field(
        default = '/',
        min_length = 1,
    )
    protocol: Protocol = Field(
        default=Protocol.https,
    )
    first_seen: datetime
    last_seen: datetime
    retire_at: datetime | None = Field(default = None) 

    # TODO: probably need more index for searching
    __table_args__ = (
        UniqueConstraint('part_of_service_id', 'hostname', 'port', 'protocol', 'path'),
    )


class EndpointTable(Endpoint, table = True):
    __tablename__ = 'endpoint'
    service: Optional['ServiceTable'] = Relationship(back_populates = 'endpoints')
    scans: list['ScanTable'] = Relationship(back_populates = 'endpoint')
