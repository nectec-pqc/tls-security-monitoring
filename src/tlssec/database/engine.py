from sqlalchemy.engine import URL
from sqlmodel import create_engine

from tlssec.settings import get_settings


engine = create_engine(URL.create(
    **get_settings().db.model_dump()
))

# TODO: make into get_engine(settings) inside database module
