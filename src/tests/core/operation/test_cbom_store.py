import json
from datetime import datetime
from pathlib import Path

import pytest

import tlssec.core.model as m
import tlssec.core.operation as op
import tlssec.core.cbom as cbom

FIXTURE = (
    Path(__file__).parents[1]
    / 'testssl/result_cases/current_openssl_server/success.pretty.json'
)


@pytest.fixture
def result():
    return json.loads(FIXTURE.read_text())


def _endpoint(session):
    ep = m.EndpointTable(
        hostname='t.example.com', port=443,
        first_seen=datetime.now(), last_seen=datetime.now(),
    )
    session.add(ep)
    session.flush()
    return ep


def _raw_scan(session, result, ep):
    row = m.ScanTable(
        result=result, scanner=m.Scanner.testssl, belong_to_endpoint_id=ep.id,
    )
    session.add(row)
    session.flush()
    return row


def test_store_cbom_creates_linked_cbom_and_opinion(session, result):
    scan_row = _raw_scan(session, result, _endpoint(session))

    cbom_row = op.store_cbom_for_scan(session, scan_row)

    assert cbom_row.scan_id == scan_row.id
    assert cbom_row.builder_version == cbom.BUILDER_VERSION
    assert cbom_row.document['bomFormat'] == 'CycloneDX'
    assert len(cbom_row.opinions) == 1
    assert cbom_row.opinions[0].verdict['vendor']['grade'] == 'T'
    session.refresh(scan_row)
    assert scan_row.cbom.id == cbom_row.id


def test_store_cbom_without_opinion(session, result):
    scan_row = _raw_scan(session, result, _endpoint(session))
    cbom_row = op.store_cbom_for_scan(session, scan_row, with_opinion=False)
    assert cbom_row.opinions == []


def test_backfill_is_idempotent(session, result):
    ep = _endpoint(session)
    _raw_scan(session, result, ep)
    _raw_scan(session, result, ep)

    assert op.backfill_cboms(session) == 2   # both scans lacked a CBOM
    assert op.backfill_cboms(session) == 0   # now current
    assert op.backfill_opinions(session) == 0


def test_backfill_rebuilds_stale_cbom(session, result):
    scan_row = _raw_scan(session, result, _endpoint(session))
    # A CBOM produced by an older builder version must be rebuilt in place.
    stale = m.CbomTable(scan_id=scan_row.id, builder_version='0.0.0-old', document={})
    session.add(stale)
    session.flush()
    stale_id = stale.id

    assert op.backfill_cboms(session) == 1
    session.refresh(scan_row)
    assert scan_row.cbom.builder_version == cbom.BUILDER_VERSION
    assert session.get(m.CbomTable, stale_id) is None  # replaced, not duplicated


def test_backfill_opinions_for_existing_cbom(session, result):
    scan_row = _raw_scan(session, result, _endpoint(session))
    op.store_cbom_for_scan(session, scan_row, with_opinion=False)

    assert op.backfill_opinions(session) == 1
    assert op.backfill_opinions(session) == 0
