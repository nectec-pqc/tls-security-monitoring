from typing import Optional
from pathlib import PurePosixPath

from pydantic import BaseModel, ConfigDict, Field as PydanticField
from sqlalchemy import (
    Integer,
    Identity,
    UniqueConstraint,
    String,
    ForeignKey,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
    attribute_keyed_dict,
)

from tlssec.database.base import Base
from .validator import EmptyToNoneStr



class Service(BaseModel):
    """A logical service that does a single application / business function."""
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    name: str = PydanticField(
        min_length=1,
        max_length=50,
        pattern=r'^[a-zA-Z_][a-zA-Z0-9_]*$',
    )
    description: EmptyToNoneStr = None
    hostname: str = PydanticField(max_length=255)


class ServiceTable(Base):
    id: Mapped[int] = mapped_column(Integer, Identity(always=True), primary_key=True)
    name: Mapped[str] = mapped_column(String(50), index=True, unique=True)
    description: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)

    tags: Mapped[list['ServiceTagTable']] = relationship(
        secondary='service_tag_map',
        back_populates='services',
    )
    endpoints: Mapped[list['EndpointTable']] = relationship(back_populates='service')



