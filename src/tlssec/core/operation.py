import logging
_logger = logging.getLogger(__name__)

from datetime import datetime

from sqlalchemy import Engine, select, or_
from sqlalchemy.orm import Session

from tlssec.database.base import Base
import tlssec.core.model as m
import tlssec.core.cbom as cbom
import tlssec.core.opinion as opinion


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


def endpoint_identity_key(endpoint) -> tuple:
    """Stable identity of an endpoint for de-duplication.

    The hostname is the stable identity of a monitored service; the IP is a
    per-scan observation that differs between tools and rotates behind a load
    balancer / round-robin DNS. So identity keys on the hostname when present,
    falling back to the IP only for IP-only endpoints.

    Known limitation: a PTR-derived hostname is trusted the same as a
    user-supplied one; distinguishing their origin is left to later work.
    """
    host = endpoint.hostname or (
        str(endpoint.ip) if endpoint.ip is not None else None
    )
    return (host, endpoint.port, endpoint.transport_protocol)


def find_new_endpoints(
    discovered: list[m.Endpoint],
    existing: list[m.EndpointTable],
) -> list[m.Endpoint]:
    """Return discovered endpoints not already tracked.

    Matches on ``(hostname-or-ip, port, transport)`` so a service whose IP
    rotates between discovery runs is not re-added as a new endpoint each time.
    """
    existing_keys = {endpoint_identity_key(ep) for ep in existing}
    return [
        ep for ep in discovered
        if endpoint_identity_key(ep) not in existing_keys
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


def endpoint_has_scans(session: Session, endpoint: m.EndpointTable) -> bool:
    """Return True if ``endpoint`` has any recorded scan history."""
    return session.scalar(
        select(m.ScanTable.id)
        .where(m.ScanTable.belong_to_endpoint_id == endpoint.id)
        .limit(1)
    ) is not None


def delete_endpoints(session: Session, endpoints: list[m.EndpointTable]):
    """Hard-delete ``endpoints`` along with their tag associations.

    The tag rows themselves are left intact since they may be shared. Callers
    must not pass endpoints that carry scan history (see ``endpoint_has_scans``);
    those should be retired with ``set_endpoints_disabled`` instead so the
    history stays linked to them.
    """
    for endpoint in endpoints:
        session.delete(endpoint)


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


# --- CBOM / opinion layers -------------------------------------------------

def store_opinion_for_cbom(
    session: Session,
    cbom_row: m.CbomTable,
    scan_row: m.ScanTable,
) -> m.OpinionTable:
    """Derive and persist an opinion (Layer 3) for a stored CBOM."""
    record = opinion.derive(cbom_row, scan_row)
    opinion_row = m.OpinionTable(
        cbom_id=cbom_row.id,
        ruleset_version=record.ruleset_version,
        verdict=record.verdict,
    )
    session.add(opinion_row)
    session.flush()
    return opinion_row


def store_cbom_for_scan(
    session: Session,
    scan_row: m.ScanTable,
    *,
    with_opinion: bool = True,
    replace: bool = False,
) -> m.CbomTable:
    """Build and persist the CBOM (Layer 2) for a raw scan.

    With ``replace``, an existing CBOM for the scan is discarded first (its
    opinions cascade away), so a stale CBOM can be rebuilt in place. Passing an
    already-current scan without ``replace`` would violate the 1:1 constraint,
    so callers backfilling should use ``replace=True``.
    """
    if replace and scan_row.cbom is not None:
        session.delete(scan_row.cbom)
        session.flush()
    record = cbom.build(scan_row)
    cbom_row = m.CbomTable(
        scan_id=scan_row.id,
        builder_version=record.builder_version,
        document=record.document,
    )
    session.add(cbom_row)
    session.flush()
    if with_opinion:
        store_opinion_for_cbom(session, cbom_row, scan_row)
    return cbom_row


def scans_needing_cbom(session: Session) -> list[m.ScanTable]:
    """Raw scans with no CBOM, or a CBOM built by a different builder version."""
    return list(session.scalars(
        select(m.ScanTable)
        .outerjoin(m.CbomTable, m.CbomTable.scan_id == m.ScanTable.id)
        .where(or_(
            m.CbomTable.id.is_(None),
            m.CbomTable.builder_version != cbom.BUILDER_VERSION,
        ))
    ).all())


def cboms_needing_opinion(session: Session) -> list[m.CbomTable]:
    """CBOMs lacking an opinion at the current ruleset version."""
    current = select(m.OpinionTable.cbom_id).where(
        m.OpinionTable.ruleset_version == opinion.RULESET_VERSION
    )
    return list(session.scalars(
        select(m.CbomTable).where(m.CbomTable.id.not_in(current))
    ).all())


def backfill_cboms(session: Session, *, with_opinion: bool = True) -> int:
    """(Re)build CBOMs for every raw scan lacking a current one. Returns count."""
    scans = scans_needing_cbom(session)
    for scan_row in scans:
        store_cbom_for_scan(session, scan_row, with_opinion=with_opinion, replace=True)
    return len(scans)


def backfill_opinions(session: Session) -> int:
    """Derive opinions for CBOMs lacking a current-ruleset opinion. Returns count."""
    cbom_rows = cboms_needing_opinion(session)
    for cbom_row in cbom_rows:
        store_opinion_for_cbom(session, cbom_row, cbom_row.scan)
    return len(cbom_rows)
