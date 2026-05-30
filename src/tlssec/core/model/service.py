from sqlmodel import Field, Relationship
from sqlalchemy import Column, Integer, Identity

from tlssec.database.sqlmodel import SQLModel


class ServiceTagMap(SQLModel): 
    service_id: int  = Field(
        primary_key = True,
        foreign_key = 'service.id',
    )
    tag_id: int = Field(
        primary_key = True,
        foreign_key = 'service_tag.id',
        # Postgres don't automatically create index on foreign key.
        # So, unless the foreign key is already a prefix of primary key (like service_id),
        # we need to explicitly create an index.
        index = True,
    )


class ServiceTagMapTable(ServiceTagMap, table = True): 
    pass


class Service(SQLModel):
    """A Logical service that does a single application / bussiness function.

    The same service may be served on multiple endpoints.
    The endpoint that serve this service may change over time.
    """
    id: int | None = Field(
        default = None,
        sa_column = Column(Integer, Identity(always = True), primary_key = True)
    )
    description: str | None = Field(
        default = None,
        description = 'A few sentences on what this service is and what it provides',
    )


class ServiceTable(Service, table = True):
    tags: list['ServiceTagTable'] = Relationship(
        back_populates = 'services',
        link_model = ServiceTagMapTable,
    )


class ServiceTag(SQLModel):
    """Tags to help organize and search for service"""
    id: int | None = Field(
        default = None,
        sa_column = Column(Integer, Identity(always = True), primary_key = True)
    )
    parent_id: int | None = Field(
        default = None,
        foreign_key = 'service_tag.id',
        index = True,
        ondelete = 'SET NULL',
        description = (
            'Parent tag this tag belongs to.'
            ' Effectively, parent tag is automatically applied when its children tag is applied.',
        ),
    )
    name: str
    description: str | None = None


class ServiceTagTable(ServiceTag, table = True):
    parent: ServiceTagTable = Relationship(
        back_populates = 'children',
        sa_relationship_kwargs = {'remote_side': 'service_tag.id'},
    )
    children: list['ServiceTagTable'] = Relationship(back_populates = 'parent')
    services: list['ServiceTable'] = Relationship(
        back_populates = 'tags',
        link_model = ServiceTagMapTable,
    )
