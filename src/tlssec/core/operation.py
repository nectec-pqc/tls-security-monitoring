import logging
_logger = logging.getLogger(__name__)

from datetime import datetime

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
                # Validate the segment name (charset/length) before persisting so
                # a malformed tag never lands in the database.
                m.Tag(name=tag)
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


def select_endpoints(
    session: Session,
    ids: list[int] = (),
    tag_paths: list[str] = (),
    ips: list[str] = (),
    hostnames: list[str] = (),
    port: int | None = None,
) -> list[m.EndpointTable]:
    """Select endpoints matching ALL of the given criteria (intersection).

    Each provided option adds a constraint the endpoint must satisfy:
    ``ids``/``ips``/``hostnames`` match when the endpoint's value is one of the
    listed values (OR within a single option), ``tag_paths`` requires the
    endpoint to carry ALL listed tags, and ``port`` pins the port. Because the
    options are ANDed together, combining e.g. ``ips`` + ``hostnames`` + ``port``
    narrows down toward a single endpoint rather than widening the match.
    Disabled (retired) endpoints are included so they can be re-enabled.

    Raises ValueError if any explicitly requested id does not exist.
    """
    missing = [
        endpoint_id for endpoint_id in ids
        if session.get(m.EndpointTable, endpoint_id) is None
    ]
    if missing:
        raise ValueError(f'no endpoint with id(s): {", ".join(map(str, missing))}')

    query = select(m.EndpointTable)
    if ids:
        query = query.where(m.EndpointTable.id.in_(ids))
    if ips:
        query = query.where(m.EndpointTable.ip.in_(ips))
    if hostnames:
        query = query.where(m.EndpointTable.hostname.in_(hostnames))
    if port is not None:
        query = query.where(m.EndpointTable.port == port)
    for tag_path in tag_paths:
        tag_row = resolve_tag(session, tag_path, create_non_existing_tag=False)
        if tag_row is None:
            # A required tag does not exist, so nothing can match all criteria.
            return []
        query = query.where(m.EndpointTable.tags.any(m.TagTable.id == tag_row.id))

    return list(session.scalars(query).all())


def add_endpoint_tag(session: Session, endpoint: m.EndpointTable, tag_path: str):
    """Attach ``tag_path`` to ``endpoint`` (idempotent)."""
    tag = resolve_tag(session, tag_path)
    if tag not in endpoint.tags:
        endpoint.tags.append(tag)
    return tag


def remove_endpoint_tag(session: Session, endpoint: m.EndpointTable, tag_path: str) -> bool:
    """Detach ``tag_path`` from ``endpoint``. Returns True if a tag was removed."""
    tag = resolve_tag(session, tag_path, create_non_existing_tag=False)
    if tag is not None and tag in endpoint.tags:
        endpoint.tags.remove(tag)
        return True
    return False


def change_endpoint_tag(
    session: Session,
    endpoint: m.EndpointTable,
    old_tag_path: str,
    new_tag_path: str,
) -> bool:
    """Replace ``old_tag_path`` with ``new_tag_path`` on ``endpoint``.

    Only adds the new tag if the old one was actually present, so a mistyped
    old tag does not silently attach an unrelated new tag. Returns True when
    the replacement happened, False when ``old_tag_path`` was not on the
    endpoint (in which case nothing is changed).
    """
    if not remove_endpoint_tag(session, endpoint, old_tag_path):
        return False
    add_endpoint_tag(session, endpoint, new_tag_path)
    return True


def set_endpoints_disabled(
    session: Session,
    endpoints: list[m.EndpointTable],
    disabled: bool,
):
    """Toggle scan participation for ``endpoints`` without touching their tags.

    Disabling stamps ``retire_at`` with the current time (recording when the
    endpoint was disabled). An already-disabled endpoint keeps its original
    timestamp so re-disabling never loses when it was first disabled. Enabling
    clears ``retire_at`` back to None. A non-empty ``retire_at`` therefore means
    "disabled", and empty means "active".
    """
    now = datetime.now()
    for endpoint in endpoints:
        if disabled:
            if endpoint.retire_at is None:
                endpoint.retire_at = now
        else:
            endpoint.retire_at = None


def make_endpoint(session, port, ip, hostname, tags=()):
    now = datetime.now()
    endpoint = m.EndpointTable(
        port=port,
        ip=ip,
        hostname=hostname,
        first_seen=now,
        last_seen=now,
    )
    session.add(endpoint)
    session.flush()
    for tag in tags:
        leaf_tag = resolve_tag(session, tag)
        endpoint.tags.append(leaf_tag)
    return endpoint
