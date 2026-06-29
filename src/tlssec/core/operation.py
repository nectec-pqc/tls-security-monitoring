import logging

from tlssec.core.model import service
_logger = logging.getLogger(__name__)

import yaml
from sqlalchemy import Engine, select
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

def resolve_tag(session, full_tag):
    tags = full_tag.split("/")
    parent_tag = None
    for tag in tags:
        isTagThere = session.scalar(
            select(m.ServiceTagTable)
            .where(m.ServiceTagTable.parent_id == (parent_tag.id if parent_tag else None))
            .where(m.ServiceTagTable.name == tag))
        if isTagThere is None:
            isTagThere = m.ServiceTagTable(name=tag, parent=parent_tag)
            session.add(isTagThere)
            session.flush()
        parent_tag = isTagThere
    return parent_tag

def resolve_service():
    pass
