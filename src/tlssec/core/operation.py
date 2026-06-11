import logging
_logger = logging.getLogger(__name__)

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from tlssec.database.base import Base
import tlssec.core.model as model


def drop_database(engine: Engine):
    _logger.info('dropping all existing tables and its content')
    Base.metadata.drop_all(engine)


def initialize_database(engine: Engine):
    _logger.info('initializing database')
    Base.metadata.create_all(engine)


def import_scan(
    scan: model.Scan,
    *,
    session: Session,
):
    if not isinstance(scan, model.ScanTable):
        scan = model.ScanTable(**scan.model_dump(exclude=['id']))
    session.add(scan)
