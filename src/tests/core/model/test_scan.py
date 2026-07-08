from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from sqlalchemy import select

import tlssec.core.model as m

NOW = datetime(2025, 1, 1, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_endpoint(session, hostname='target.example.com'):
    ep = m.EndpointTable(
        hostname=hostname,
        port=443,
        application_protocol='https',
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(ep)
    session.flush()
    return ep


# ---------------------------------------------------------------------------
# Pydantic validation
# ---------------------------------------------------------------------------

def test_scan_requires_result():
    with pytest.raises(ValidationError):
        m.Scan(belong_to_endpoint_id=1)


def test_scan_result_can_be_dict():
    s = m.Scan(result={'key': 'value'}, belong_to_endpoint_id=1)
    assert s.result == {'key': 'value'}


def test_scan_result_can_be_list():
    s = m.Scan(result=[{'id': 'TLS1_3', 'finding': 'offered'}], belong_to_endpoint_id=1)
    assert isinstance(s.result, list)


def test_scan_optional_fields_default_to_none():
    s = m.Scan(result={}, belong_to_endpoint_id=1)
    assert s.id is None
    assert s.start_time is None
    assert s.time_taken is None


def test_scan_from_file(tmp_path):
    data = [{'id': 'TLS1_2', 'finding': 'offered'}]
    scan_file = tmp_path / 'result.yaml'
    scan_file.write_text(yaml.dump(data))

    s = m.Scan.from_file(scan_file)
    assert s.result == data


def test_scan_from_file_bad_path():
    with pytest.raises(ValueError, match='Can not load'):
        m.Scan.from_file(Path('/nonexistent/file.yaml'))


# ---------------------------------------------------------------------------
# ORM / DB integration
# ---------------------------------------------------------------------------

def test_create_and_query_scan(session):
    ep = make_endpoint(session)

    scan = m.ScanTable(
        result={'tls': 'ok'},
        belong_to_endpoint_id=ep.id,
        start_time=NOW,
        time_taken=42,
    )
    session.add(scan)
    session.flush()

    result = session.scalars(
        select(m.ScanTable).where(m.ScanTable.id == scan.id)
    ).one()
    assert result.result == {'tls': 'ok'}
    assert result.start_time == NOW
    assert result.time_taken == 42
    assert result.belong_to_endpoint_id == ep.id


def test_scan_optional_fields_nullable(session):
    ep = make_endpoint(session)

    scan = m.ScanTable(result=[], belong_to_endpoint_id=ep.id)
    session.add(scan)
    session.flush()

    result = session.scalars(
        select(m.ScanTable).where(m.ScanTable.id == scan.id)
    ).one()
    assert result.start_time is None
    assert result.time_taken is None


def test_scan_result_list_stored_as_jsonb(session):
    ep = make_endpoint(session)

    data = [{'id': 'TLS1_3', 'finding': 'offered'}, {'id': 'TLS1_2', 'finding': 'offered'}]
    scan = m.ScanTable(result=data, belong_to_endpoint_id=ep.id)
    session.add(scan)
    session.flush()

    result = session.scalars(
        select(m.ScanTable).where(m.ScanTable.id == scan.id)
    ).one()
    assert result.result == data


def test_scan_endpoint_relationship(session):
    ep = make_endpoint(session)

    scan = m.ScanTable(result={}, belong_to_endpoint_id=ep.id)
    session.add(scan)
    session.flush()
    session.refresh(scan)

    assert scan.endpoint.id == ep.id
    assert scan.endpoint.hostname == 'target.example.com'


def test_endpoint_scans_relationship(session):
    ep = make_endpoint(session)

    scans = [m.ScanTable(result={'run': i}, belong_to_endpoint_id=ep.id) for i in range(3)]
    session.add_all(scans)
    session.flush()
    session.refresh(ep)

    assert len(ep.scans) == 3


def test_scan_from_attributes(session):
    ep = make_endpoint(session)

    scan = m.ScanTable(result={'key': 'val'}, belong_to_endpoint_id=ep.id, time_taken=10)
    session.add(scan)
    session.flush()

    pydantic_scan = m.Scan.model_validate(scan)
    assert pydantic_scan.result == {'key': 'val'}
    assert pydantic_scan.time_taken == 10
    assert pydantic_scan.belong_to_endpoint_id == ep.id
