import json
from pathlib import Path

import pytest

import tlssec.core.model as m
import tlssec.core.cbom as cbom
import tlssec.core.opinion as opinion

FIXTURE = (
    Path(__file__).parents[1]
    / 'testssl/result_cases/current_openssl_server/success.pretty.json'
)


@pytest.fixture
def scan():
    return m.Scan(
        result=json.loads(FIXTURE.read_text()),
        scanner=m.Scanner.testssl,
        id=1,
    )


@pytest.fixture
def verdict(scan):
    cbom_rec = cbom.build(scan)
    cbom_rec.id = 5
    return opinion.derive(cbom_rec, scan)


def test_opinion_metadata(verdict):
    assert verdict.ruleset_version == opinion.RULESET_VERSION
    assert verdict.cbom_id == 5


def test_quantum_pqc_capable_but_not_fully_safe(verdict):
    q = verdict.verdict['quantum']
    # Fixture offers the X25519MLKEM768 hybrid -> PQC capable...
    assert q['pqc_capable'] is True
    assert 'X25519MLKEM768' in q['safe_key_establishment']
    # ...but classical key exchange and 128-bit symmetric are still offered.
    assert 'X25519' in q['unsafe_key_establishment']
    assert any(s.startswith('AES128') for s in q['unsafe_symmetric'])
    assert 'AES256-GCM' in q['safe_symmetric']
    assert q['quantum_safe'] is False


def test_weakness_none_for_modern_config(verdict):
    w = verdict.verdict['weakness']
    assert w['weak_protocols'] == []   # only TLS 1.2 / 1.3 offered
    assert w['weak_ciphers'] == []     # no RC4 / 3DES / DES
    assert w['is_weak'] is False


def test_certificate_self_signed_and_expired(verdict):
    cert = verdict.verdict['certificate']
    assert cert['self_signed'] is True          # issuer == subject == localhost
    assert cert['expired'] is True              # notValidAfter is 2026-07-11 (past)


def test_vendor_verdict_captured(verdict):
    vendor = verdict.verdict['vendor']
    assert vendor['tool'] == 'testssl'
    assert vendor['grade'] == 'T'               # testssl's own rating
    assert isinstance(vendor['vulnerabilities'], list)


SSH_FIXTURE = (
    Path(__file__).parents[1] / 'sshaudit/result_cases/openssh_server.json'
)


def test_ssh_opinion_from_real_fixture():
    scan = m.Scan(
        result=json.loads(SSH_FIXTURE.read_text()),
        scanner=m.Scanner.ssh_audit,
        id=2,
    )
    cbom_rec = cbom.build(scan)
    cbom_rec.id = 6
    v = opinion.derive(cbom_rec, scan).verdict

    # OpenSSH offers mlkem/sntrup hybrids -> recognized via CBOM nist level.
    assert v['quantum']['pqc_capable'] is True
    assert 'mlkem768x25519-sha256' in v['quantum']['safe_key_establishment']

    vendor = v['vendor']
    assert vendor['tool'] == 'ssh-audit'
    assert vendor['software'] == 'OpenSSH_10.3'
    assert isinstance(vendor['flagged'], list)
