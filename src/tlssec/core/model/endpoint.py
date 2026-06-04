from datetime import datetime
from typing import Optional, Literal

from sqlmodel import Field, Relationship
from sqlalchemy import Column, Integer, Identity, UniqueConstraint

from tlssec.database.sqlmodel import SQLModel  

Protocol = Literal['tcp', 'udp', 'http', 'https']

class EndPoint(SQLModel):
    id: int | None = Field(
        default=None,
        sa_column=Column(Integer, Identity(always=True), primary_key=True),
    )
    part_of_service_id: int = Field(foreign_key='service.id', index=True)
    hostname: str = Field(max_length=253)
    port: int = Field(ge=1)
    part: str = Field(default='/') 
    protocol: Protocol = 'tcp'
    first_seen: datetime
    last_seen: datetime
    retire_at: datetime | None = Field(default=None) 

    __table_args__ = (
        UniqueConstraint('part_of_service_id', 'hostname', 'port', 'protocol', 'path'),
    )

class EndPointTable(EndPoint, table=True):
    target: Optional['ServiceTable'] = Relationship(back_populates='endpoints')
    scans: list['ScanTable'] = Relationship(back_populates='scans')


