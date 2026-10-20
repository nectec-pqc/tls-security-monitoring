from datetime import datetime
import re

from sqlalchemy import (
    DateTime,
)
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import DeclarativeBase, declared_attr


def to_snake_case(name: str) -> str:
    return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()


class Base(DeclarativeBase):
    """Customized SQLAlchemy declarative base.

    - Names tables with snake_case automatically
    - Strips _table suffix from class name
    - Add pretty representations
    - Customized type mapping
    """
    type_annotation_map = {
        datetime: DateTime(timezone = True),
    }

    @declared_attr.directive
    def __tablename__(cls) -> str:
        return to_snake_case(cls.__name__).removesuffix('_table')

    def __repr_args__(self):
        mapper = inspect(self).mapper
        return [
            (col.key, getattr(self, col.key))
            for col in mapper.column_attrs
        ]

    def __repr__(self):
        attrs = ', '.join(f'{name}={value!r}' for name, value in self.__repr_args__())
        class_name = self.__class__.__name__
        return f'{class_name}({attrs})'

    def __rich_repr__(self):
        """Used by Rich (https://rich.readthedocs.io/en/stable/pretty.html) to pretty print objects."""
        for name, value in self.__repr_args__():
            yield name, value
