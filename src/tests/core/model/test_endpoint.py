from contextlib import nullcontext
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

import tlssec.core.model as m

NOW = datetime(2025, 1, 1, tzinfo=timezone.utc)
LATER = datetime(2025, 6, 1, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Pydantic validation
# ---------------------------------------------------------------------------

VALID_ENDPOINT_ARGS = dict(
    hostname='target.example.com',
    first_seen=NOW,
    last_seen=NOW,
)


@pytest.mark.parametrize(
    'overrides, expectation',
    [
        pytest.param({}, nullcontext(), id='minimal valid endpoint'),
        pytest.param({'port': 8443}, nullcontext(), id='custom port'),
        pytest.param({'path': '/api/v2'}, nullcontext(), id='non-root path'),
        pytest.param({'ip': '192.168.1.1'}, nullcontext(), id='with IPv4'),
        pytest.param({'ip': '::1'}, nullcontext(), id='with IPv6'),
        pytest.param({'retire_at': LATER}, nullcontext(), id='with retire_at'),
        pytest.param({'hostname': ''}, pytest.raises(ValidationError), id='empty hostname'),
        pytest.param({'hostname': 'x' * 254}, pytest.raises(ValidationError), id='hostname too long'),
        pytest.param({'port': 0}, pytest.raises(ValidationError), id='port zero'),
        pytest.param({'port': 65536}, pytest.raises(ValidationError), id='port too large'),
        pytest.param({'path': 'no-leading-slash'}, pytest.raises(ValidationError), id='path missing leading slash'),
        pytest.param({'path': '/with?query'}, pytest.raises(ValidationError), id='path with query string'),
        pytest.param({'path': '/with#fragment'}, pytest.raises(ValidationError), id='path with fragment'),
    ],
)
def test_endpoint_validation(overrides, expectation):
    with expectation:
        m.Endpoint(**(VALID_ENDPOINT_ARGS | overrides))


def test_endpoint_defaults():
    ep = m.Endpoint(**VALID_ENDPOINT_ARGS)
    assert ep.port == 443
    assert ep.path == '/'
    assert ep.application_protocol == 'https'
    assert ep.ip is None
    assert ep.retire_at is None


def test_endpoint_from_attributes(session):
    orm_ep = m.EndpointTable(
        hostname='target.example.com',
        port=8443,
        path='/api',
        application_protocol = 'https',
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(orm_ep)
    session.flush()

    pydantic_ep = m.Endpoint.model_validate(orm_ep)
    assert pydantic_ep.hostname == 'target.example.com'
    assert pydantic_ep.port == 8443
    assert pydantic_ep.path == '/api'


def make_endpoint(session, **overrides):
    defaults = dict(
        hostname = 'target.example.com',
        ip = '127.0.0.1',
        port = 443,
        path = '/',
        application_protocol = 'https',
        first_seen = NOW,
        last_seen = NOW,
    )
    ep = m.EndpointTable(**(defaults | overrides))
    session.add(ep)
    session.flush()
    return ep


def test_create_and_query_endpoint(session):
    ep = make_endpoint(session)

    result = session.scalars(
        select(m.EndpointTable).where(m.EndpointTable.id == ep.id)
    ).one()

    assert result.hostname == 'target.example.com'
    assert result.port == 443
    assert result.path == '/'
    assert result.application_protocol == 'https'
    assert result.first_seen == NOW
    assert result.last_seen == NOW
    assert result.retire_at is None


def test_different_port_is_allowed(session):
    make_endpoint(session, port=443)
    make_endpoint(session, port=8443)

    results = session.scalars(select(m.EndpointTable)).all()
    assert len(results) == 2


def test_retire_at_can_be_set(session):
    ep = make_endpoint(session, retire_at=LATER)

    result = session.scalars(
        select(m.EndpointTable).where(m.EndpointTable.id == ep.id)
    ).one()
    assert result.retire_at == LATER


def test_different_application_protocol_is_allowed(session):
    # application_protocol is not part of the scan identity, so vary the port to
    # keep the two rows distinct.
    make_endpoint(session, port=443, application_protocol = 'ftp')
    make_endpoint(session, port=8443, application_protocol = 'smtp')

    results = session.scalars(select(m.EndpointTable)).all()
    assert len(results) == 2


def test_different_path_is_allowed(session):
    # path is not part of the scan identity, so vary the port to keep the two
    # rows distinct.
    make_endpoint(session, port=443, path='/')
    make_endpoint(session, port=8443, path='/api/v1')

    results = session.scalars(select(m.EndpointTable)).all()
    assert len(results) == 2


def test_different_hostname_is_allowed(session):
    make_endpoint(session, hostname='a.example.com')
    make_endpoint(session, hostname='b.example.com')

    results = session.scalars(select(m.EndpointTable)).all()
    assert len(results) == 2


def test_duplicate_endpoint_identity_is_rejected(session):
    # Same scan identity (hostname-or-ip, port, transport) -> the
    # uq_endpoint_identity index rejects the second insert.
    make_endpoint(session)
    with pytest.raises(IntegrityError):
        make_endpoint(session)
    session.rollback()


def test_same_hostname_and_ip_share_identity(session):
    # A hostname-only row and a hostname+ip row for the same host collide:
    # identity keys on the hostname, so the ip does not make them distinct.
    make_endpoint(session, hostname='dup.example.com', ip=None)
    with pytest.raises(IntegrityError):
        make_endpoint(session, hostname='dup.example.com', ip='203.0.113.9')
    session.rollback()


def test_ip_only_endpoints_are_unique_by_ip(session):
    # With no hostname, identity falls back to the ip.
    make_endpoint(session, hostname=None, ip='203.0.113.1')
    make_endpoint(session, hostname=None, ip='203.0.113.2')
    assert len(session.scalars(select(m.EndpointTable)).all()) == 2

    with pytest.raises(IntegrityError):
        make_endpoint(session, hostname=None, ip='203.0.113.1')
    session.rollback()
