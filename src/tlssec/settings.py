from typing import Literal

from pydantic import (
    BaseModel,
    Field,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from tlssec.core.model.validator import PandasTimedelta


class DatabaseSettings(BaseModel):
    """Matches arguments of `sqlalchemy.URL.create()`"""
    # NOTE: `tlssec` needs asyncio support, so DBAPI choice narrows down to just `psycopg` or `asyncpg`
    # `psycopg` is choosen for wider compatibility (due to popularity), but may be replaced by `asyncpg` later for performance.
    drivername: str = 'postgresql+psycopg'
    username: str = 'postgres'
    password: str
    host: str = None
    port: int = None
    database: str = 'tlssec'


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix = 'TLSSEC_',
        env_nested_delimiter = '__',
    )

    deployment_mode: Literal['development', 'production'] = 'production'
    db: DatabaseSettings
    endpoint_cooldown: PandasTimedelta('seconds') = Field(
        default = '7 days',
        description = 'Seconds to wait from last successful scan before getting scanned again',
    )
