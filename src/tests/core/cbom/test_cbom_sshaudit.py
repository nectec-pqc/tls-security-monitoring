import json
from pathlib import Path

import pytest

import tlssec.core.model as m
import tlssec.core.cbom as cbom

FIXTURE = (
    Path(__file__).parents[1] / 'sshaudit/result_cases/openssh_server.json'
)


@pytest.fixture
def document():
    result = json.loads(FIXTURE.read_text())
    return cbom.build(m.Scan(result=result, scanner=m.Scanner.ssh_audit)).document


def _by_type(doc):
    out = {}
    for c in doc['components']:
        out.setdefault(c['cryptoProperties']['assetType'], []).append(c)
    return out


def test_single_ssh_protocol_links_negotiated_algorithms(document):
    protos = _by_type(document)['protocol']
    assert len(protos) == 1
    pp = protos[0]['cryptoProperties']['protocolProperties']
    assert pp['type'] == 'ssh'
    assert pp['version'] == '2.0'
    # Every linked ref resolves to a real component (SSH has no cipher suites).
    refs = set(pp['cryptoRefArray'])
    assert refs
    assert refs <= {c['bom-ref'] for c in document['components']}


def test_pqc_kex_tagged_with_nist_level(document):
    kems = {
        a['name']: a['cryptoProperties']['algorithmProperties']
        for a in _by_type(document)['algorithm']
        if a['cryptoProperties']['algorithmProperties'].get('primitive') == 'kem'
    }
    assert kems['mlkem768x25519-sha256']['nistQuantumSecurityLevel'] == 3
    assert any('sntrup761' in name for name in kems)


def test_host_keys_are_signature_algorithms(document):
    sigs = {
        a['name'] for a in _by_type(document)['algorithm']
        if a['cryptoProperties']['algorithmProperties'].get('primitive') == 'signature'
    }
    assert any(s.startswith(('ssh-ed25519', 'ecdsa-', 'rsa-', 'ssh-rsa')) for s in sigs)


def test_pqc_host_key_tagged_with_nist_level():
    # The openssh_server fixture offers only classical host keys, so build a
    # minimal result to cover the ML-DSA path.
    result = {'key': [{'algorithm': 'ssh-mldsa65'}, {'algorithm': 'ssh-ed25519'}]}
    doc = cbom.build(m.Scan(result=result, scanner=m.Scanner.ssh_audit)).document
    sigs = {
        a['name']: a['cryptoProperties']['algorithmProperties']
        for a in _by_type(doc)['algorithm']
    }
    assert sigs['ssh-mldsa65']['nistQuantumSecurityLevel'] == 3
    assert sigs['ssh-ed25519'].get('nistQuantumSecurityLevel') is None


def test_cipher_primitive_and_mode(document):
    algos = {
        a['name']: a['cryptoProperties']['algorithmProperties']
        for a in _by_type(document)['algorithm']
    }
    chacha = next(v for k, v in algos.items() if k.startswith('chacha20'))
    assert chacha['primitive'] == 'stream-cipher'
    gcm = next((v for k, v in algos.items() if 'gcm' in k), None)
    if gcm is not None:
        assert gcm['primitive'] == 'block-cipher'
        assert gcm['mode'] == 'gcm'


def test_fingerprints_become_digest_material(document):
    digests = _by_type(document)['related-crypto-material']
    assert digests
    props = digests[0]['cryptoProperties']['relatedCryptoMaterialProperties']
    assert props['type'] == 'digest'
    assert props['format'] in ('SHA256', 'MD5')


def test_pseudo_kex_markers_excluded(document):
    names = {c['name'] for c in document['components']}
    assert not any(n.startswith(('ext-info-', 'kex-strict-')) for n in names)


def test_document_is_valid_cyclonedx_16(document):
    from cyclonedx.validation.json import JsonStrictValidator
    from cyclonedx.schema import SchemaVersion
    errors = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(document))
    assert errors is None
