from sqlmodel import Field, Relationship
from sqlalchemy import Column, Integer, Identity


from tlssec.database.sqlmodel import SQLModel

class Target(SQLModel):
    id: int | None = Field(
        default = None,
        sa_column = Column(Integer, Identity(always = True), primary_key = True),
    )
    hostname: str = Field(
        index = True,
        max_length = 253,
    )


class TargetTable(Target, table = True):
    pass
