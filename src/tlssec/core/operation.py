import logging
_logger = logging.getLogger(__name__)

from sqlalchemy import Engine
from sqlmodel import (
    SQLModel,
    Session,
)

import tlssec.core.model as model


def initialize_database(engine: Engine):
    _logger.info('initializing database')
    SQLModel.metadata.create_all(engine)


def import_scan(
    scan: model.Scan,
    *,
    session: Session,
):
    if not isinstance(scan, model.ScanTable):
        scan = model.ScanTable(**scan.model_dump(exclude = ['id']))
    session.add(scan)
