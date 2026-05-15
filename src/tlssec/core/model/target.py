from sqlmodel import SQLModel, Field, Relationship


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
