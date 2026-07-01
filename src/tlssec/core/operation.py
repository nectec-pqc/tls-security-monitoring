import logging
_logger = logging.getLogger(__name__)

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
        scan = m.ScanTable(**scan.m_dump(exclude=['id']))
    session.add(scan)


def resolve_tag(session, full_tag):
    tags = full_tag.split("/")
    parent_tag = None
    for tag in tags:
        existing = session.scalar(
            select(m.TagTable)
            .where(m.TagTable.parent_id == (parent_tag.id if parent_tag else None))
            .where(m.TagTable.name == tag))
        if existing is None:
            existing = m.TagTable(name=tag, parent=parent_tag)
            session.add(existing)
            session.flush()
        parent_tag = existing
    return parent_tag


def make_endpoint(session, port, ip, hostname, tags=()):
    endpoint = m.EndpointTable(
        port=port,
        ip=ip,
        hostname=hostname,
    )
    session.add(endpoint)
    session.flush()
    for tag in tags:
        leaf_tag = resolve_tag(session, tag)
        endpoint.tags.append(leaf_tag)
    return endpoint
