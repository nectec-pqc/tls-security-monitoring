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


def resolve_tag(
    session: Session, 
    full_tag: str,
    create_non_existing_tag: bool = True,
):
    tags = full_tag.split("/")
    parent_tag = None
    for tag in tags:
        existing = session.scalar(
            select(m.TagTable)
            .where(m.TagTable.parent_id == (parent_tag.id if parent_tag else None))
            .where(m.TagTable.name == tag))
        if existing is None:
            if create_non_existing_tag:
                existing = m.TagTable(name=tag, parent=parent_tag)
                session.add(existing)
                session.flush()
            else:
                return None
        parent_tag = existing
    return parent_tag

def get_endpoints_by_tag(
    session: Session,
    tag_paths: list[str],
) -> list[m.EndpointTable]:
    """Return endpoints that have ALL of the given exact tags."""
    query = select(m.EndpointTable)
    for tag_path in tag_paths:
        tag_row = resolve_tag(session, tag_path, False)
        if tag_row is None:
            return []
        query = query.where(
            m.EndpointTable.tags.any(m.TagTable.id == tag_row.id)
        )
    return list(session.scalars(query).all())


def find_new_endpoints(
    discovered: list[m.Endpoint],
    existing: list[m.EndpointTable],
) -> list[m.Endpoint]:
    """Return discovered endpoints not already in DB.

    Match on (ip, port, transport_protocol).
    """
    existing_keys = {
        (str(ep.ip), ep.port, ep.transport_protocol)
        for ep in existing
        if ep.ip is not None
    }
    return [
        ep for ep in discovered
        if (str(ep.ip), ep.port, ep.transport_protocol) not in existing_keys
    ]


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
