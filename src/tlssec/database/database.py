from functools import cached_property

from sqlalchemy import URL, Engine
from sqlmodel import create_engine, Session

from tlssec.settings import Settings


class Database:
    """Database interface configured with app-specific settings"""

    def __init__(
        self,
        settings: Settings | None = None,
    ):
        if settings is None:
            settings = Settings()
        self.engine = create_engine(URL.create(
            **settings.db.model_dump()
        ))

    @cached_property
    def session(self) -> Session:
        return Session(self.engine)
