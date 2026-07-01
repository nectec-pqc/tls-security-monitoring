from pathlib import PurePosixPath
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field as PydanticField
from sqlalchemy import Integer, Identity, UniqueConstraint, String, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship, attribute_keyed_dict

from tlssec.database.base import Base
from .validator import EmptyToNoneStr


class Tag(BaseModel):
    """Tags to help organize and search for endpoints."""
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
        ForeignKey('tag.id', ondelete='SET NULL'),
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

    parent: Mapped[Optional['TagTable']] = relationship(
        back_populates='children',
        foreign_keys='[TagTable.parent_id]',
        remote_side='TagTable.id',
    )
    children: Mapped[dict[str, 'TagTable']] = relationship(
        back_populates='parent',
        foreign_keys='[TagTable.parent_id]',
        collection_class=attribute_keyed_dict('name'),
    )
    endpoints: Mapped[list['EndpointTable']] = relationship(
        secondary='endpoint_tag_map',
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


class EndpointTagMapTable(Base):
    endpoint_id: Mapped[int] = mapped_column(ForeignKey('endpoint.id'), primary_key=True)
    tag_id: Mapped[int] = mapped_column(ForeignKey('tag.id'), primary_key=True, index=True)
