import logging

from tlssec.core.model import service
_logger = logging.getLogger(__name__)

import yaml
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

def parse(yaml_content):
    raw_services = yaml.safe_load(yaml_content)
    services = []
    for raw_service in raw_services:
        service = m.Service(**raw_service)
        services.append((service, raw_service["tags"]))
    return  services

def make_service(name_and_hostname, tags):
    services = []
    name, hostname = name_and_hostname
    service = m.Service(name=name, hostname=hostname)
    services.append((service, tags))
    return services
