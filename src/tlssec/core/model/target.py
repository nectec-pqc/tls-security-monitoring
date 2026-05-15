from sqlmodel import Field, Relationship

from tlssec.database.sqlmodel import SQLModel

class Target(SQLModel):
    id: int | None = Field(
        default = None,
        primary_key = True,
    )
    hostname: str = Field(
        index = True,
        max_length = 253,
    )


class TargetTable(Target, table = True):
    pass
