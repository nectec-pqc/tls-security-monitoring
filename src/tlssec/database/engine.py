from sqlalchemy.engine import URL
from sqlmodel import (
    create_engine,
    Session,
)

from tlssec.settings import get_settings


engine = create_engine(URL.create(
    **get_settings().db.model_dump()
))


def get_session():
    with Session(engine) as session:
        yield session
