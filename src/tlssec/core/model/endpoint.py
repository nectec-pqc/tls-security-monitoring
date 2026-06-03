from datetime import datetime
from typing import Optional

from sqlmodel import Field, Relationship
from sqlalchemy import Column, Integer, Identity, UniqueConstraint

from tlssec.database.sqlmodel import SQLModel  

class EndPoint(SQLModel):
    id: int | None = Field(
        default=None,
        sa_column=Column(Integer, Identity(always=True), primary_key=True),
    )
    target_id: int = Field(foreign_key='target.id', index=True)
    hostname: str = Field(max_length=253)
    port: int
    protocol: str = Field(default='tcp')
    first_seen: datetime
    last_seen: datetime
    retired_at: datetime | None = Field(default=None, index=True)

    __table_args__ = (
        UniqueConstraint('target_id', 'hostname', 'port', 'protocol'),
    )


class EndPointTable(EndPoint, table=True):
    target: Optional['TargetTable'] = Relationship(back_populates='endpoints')
    scans: list['ScanTable'] = Relationship(back_populates='scans')
