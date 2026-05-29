from sqlmodel import Field
from sqlalchemy import Column, Integer, Identity

from tlssec.database.sqlmodel import SQLModel

class Service(SQLModel):
    """A Logical service that does a single application / bussiness function.

    The same service may be served on multiple endpoints.
    The endpoint that serve this service may change over time.
    """
    serviceID: int | None = Field(
        default = None,
        sa_column = Column(Integer, Identity(always = True), primary_key = True)
    )
    description: str | None = Field(
        default = None,
        description = 'A few sentences on what this service is and what it provides',
    )


class ServiceTable(Service, table = True):
    pass
