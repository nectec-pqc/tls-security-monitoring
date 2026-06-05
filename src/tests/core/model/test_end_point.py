from contextlib import nullcontext
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlmodel import select

import tlssec.core.model as m

NOW = datetime(2025, 1, 1, tzinfo=timezone.utc)
LATER = datetime(2025, 6, 1, tzinfo=timezone.utc)

def make_service(session, name='test_service'):
    svc = m.ServiceTable(name=name, hostname='example.com')
    session.add(svc)
    session.flush()
    return svc


def make_endpoint(session, service, **overrides):
    defaults = dict(
        part_of_service_id=service.id,
        hostname='target.example.com',
        port=443,
        path='/',
        protocol='tcp',
        first_seen=NOW,
        last_seen=NOW,
    )
    ep = m.EndPointTable(**(defaults | overrides))
    session.add(ep)
    session.flush()
    return ep

def test_create_and_query_endpoint(session):
    svc = make_service(session)
    ep = make_endpoint(session, svc)

    result = session.exec(
        select(m.EndPointTable).where(m.EndPointTable.id == ep.id)
    ).one()

    assert result.hostname == 'target.example.com'
    assert result.port == 443
    assert result.path == '/'
    assert result.protocol == 'tcp'
    assert result.first_seen == NOW
    assert result.last_seen == NOW
    assert result.retire_at is None

def test_unique_constraint_same_endpoint(session):
    """Exact same service + hostname + port + protocol + path is rejected."""
    svc = make_service(session)
    make_endpoint(session, svc)

    duplicate = m.EndPointTable(
        part_of_service_id=svc.id,
        hostname='target.example.com',
        port=443,
        path='/',
        protocol='tcp',
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(duplicate)
    with pytest.raises(IntegrityError):
        session.flush()


def test_different_port_is_allowed(session):
    svc = make_service(session)
    make_endpoint(session, svc, port=443)
    make_endpoint(session, svc, port=8443)

    results = session.exec(
        select(m.EndPointTable).where(m.EndPointTable.part_of_service_id == svc.id)
    ).all()
    assert len(results) == 2
