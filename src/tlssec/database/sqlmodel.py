import re

from sqlmodel import SQLModel as _SQLModel
from sqlalchemy.orm import declared_attr


def to_snake_case(name: str) -> str:
    return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()


class SQLModel(_SQLModel):
    """Same with sqlmodel.SQLModel but ...

    - Name table with snake_case
    - Name table without _table suffix
    """
    @declared_attr.directive
    def __tablename__(cls) -> str:
        return to_snake_case(cls.__name__).removesuffix('_table')
