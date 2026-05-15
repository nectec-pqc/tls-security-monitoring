import logging
_logger = logging.getLogger(__name__)

from sqlmodel import SQLModel

from tlssec.database.engine import engine
# NOTE: Important for SQLModel.metadata to be populated
from tlssec.core.model import *


def initialize_database():
    _logger.info('initializing database')
    SQLModel.metadata.create_all(engine)
