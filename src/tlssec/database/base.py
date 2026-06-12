import re

from sqlalchemy.orm import DeclarativeBase, declared_attr


def to_snake_case(name: str) -> str:
    return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()


class Base(DeclarativeBase):
    """SQLAlchemy declarative base.

    - Names tables with snake_case automatically
    - Strips _table suffix from class name
    """
    @declared_attr.directive
    def __tablename__(cls) -> str:
        return to_snake_case(cls.__name__).removesuffix('_table')

