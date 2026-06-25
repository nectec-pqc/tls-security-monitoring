import logging

from tlssec.core.model import service
_logger = logging.getLogger(__name__)

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from tlssec.database.base import Base
import tlssec.core.model as m


def drop_database(engine: Engine):
    _logger.info('dropping all existing tables and its content')
    Base.metadata.drop_all(engine)


def initialize_database(engine: Engine):
    _logger.info('initializing database')
    Base.metadata.create_all(engine)


def import_scan(
    scan: m.Scan | m.ScanTable,
    *,
    session: Session,
):
    if not isinstance(scan, m.ScanTable):
        scan = m.ScanTable(**scan.m_dump(exclude = ['id']))
    session.add(scan)

def parse(inputFile):
    services = []
    for rawService in inputFile:
        tags = rawService.pop("tags",[])
        service = m.Service(**rawService)
        services.append((service, tags))
    return  services

def make_service(name, tags):
    pass
