from pathlib import Path
from datetime import datetime

from sqlmodel import Field, Relationship
from sqlalchemy import Column, Integer, Identity
from sqlalchemy.dialects.postgresql import JSONB
import yaml

from tlssec.database.sqlmodel import SQLModel


class Scan(SQLModel):
    """A record about a single execution of scan"""
    id: int | None = Field(
        default = None,
        sa_column = Column(Integer, Identity(always = True), primary_key = True),
    )
    result: dict | list = Field(
        sa_type = JSONB,
        description = 'raw resulting data as output by the scanning tool',
    )
    start_time: datetime | None = Field(
        default = None,
        index = True,
    )
    time_taken: int | None = Field(
        default = None,
        description = 'seconds taken to complete the scan',
    )
    # TODO: store error in result?
    # TODO: link to scan configuration
    # TODO: impose unique constraint on result. Prevent repeated import.

    @classmethod
    def from_file(cls, path: Path):
        try:
            with path.open() as f:
                content = yaml.safe_load(f)
        except Exception as e:
            raise ValueError(f'Can not load scanning record from {path}') from e

        # TODO: Try getting start_time from content,
        # or use mtime of input file
        return cls.model_validate({
            'result': content,
        })


class ScanTable(Scan, table = True):
    pass
