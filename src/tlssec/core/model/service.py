from typing import Optional

from sqlmodel import Field, Relationship
from sqlalchemy import (
    Column,
    Integer,
    Identity,
    UniqueConstraint,
)
from sqlalchemy.orm import attribute_keyed_dict

from tlssec.database.sqlmodel import SQLModel
from .validator import EmptyToNoneStr


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
            'ID of parent tag.'
            ' Parent tag must also be applied if child tag is applied.',
        ),
    )
    name: str = Field(
        index = True,
        min_length = 1,
        max_length = 30,
        # NOTE: Can not use `regex` or `pattern` option directly because of
        # https://github.com/fastapi/sqlmodel/pull/1231
        schema_extra = {'pattern': r'^[a-zA-Z_][a-zA-Z0-9_]*$'},
        description = 'Tag name which must be unique among siblings',
    )
    description: EmptyToNoneStr = Field(
        default = None,
        max_length = 500,
    )

    __table_args__ = (
        UniqueConstraint(
            'parent_id', 'name',
            postgresql_nulls_not_distinct = True,
        ),
    )


class ServiceTagTable(ServiceTag, table = True):
    parent: Optional[ServiceTagTable] = Relationship(
        back_populates = 'children',
        sa_relationship_kwargs = {'remote_side': (lambda: ServiceTagTable.id)},
    )
    children: dict[str, ServiceTagTable] = Relationship(
        back_populates = 'parent',
        sa_relationship_kwargs = {'collection_class': attribute_keyed_dict('name')},
    )
    services: list['ServiceTable'] = Relationship(
        back_populates = 'tags',
        link_model = ServiceTagMapTable,
    )

    def __init__(self, children = None, **kwargs):
        if isinstance(children, list):
            children = {child.name: child for child in children}
        if children:
            kwargs['children'] = children
        super().__init__(**kwargs)
