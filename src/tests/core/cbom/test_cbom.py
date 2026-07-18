import json
from pathlib import Path

import pytest

import tlssec.core.model as m
import tlssec.core.cbom as cbom

FIXTURE = (
    Path(__file__).parents[1]
    / 'testssl/result_cases/current_openssl_server/success.pretty.json'
)


@pytest.fixture
def document():
    result = json.loads(FIXTURE.read_text())
    return cbom.build(m.Scan(result=result, scanner=m.Scanner.testssl)).document


def _by_type(doc):
    out = {}
    for c in doc['components']:
        out.setdefault(c['cryptoProperties']['assetType'], []).append(c)
    return out


def test_all_four_asset_types_present(document):
    types = {c['cryptoProperties']['assetType'] for c in document['components']}
    assert types == {'algorithm', 'certificate', 'protocol', 'related-crypto-material'}


def test_only_offered_tls_versions_become_protocols(document):
    versions = {
        c['cryptoProperties']['protocolProperties']['version']
        for c in _by_type(document)['protocol']
    }
    # Fixture offers TLS 1.2 and 1.3; SSLv2/3 and TLS 1.0/1.1 are "not offered".
    assert versions == {'1.2', '1.3'}


def test_cipher_suites_have_iana_name_and_hex_identifier(document):
    suites = [
        s
        for p in _by_type(document)['protocol']
        for s in p['cryptoProperties']['protocolProperties'].get('cipherSuites', [])
    ]
    assert suites
    for s in suites:
        assert s['name'].startswith('TLS_')
        assert s['identifiers'] and all(i.startswith('0x') for i in s['identifiers'])


def test_pqc_kem_tagged_with_nist_level(document):
    kems = [
        a for a in _by_type(document)['algorithm']
        if a['cryptoProperties']['algorithmProperties'].get('primitive') == 'kem'
    ]
    by_name = {a['name']: a['cryptoProperties']['algorithmProperties'] for a in kems}
    assert 'X25519MLKEM768' in by_name
    assert by_name['X25519MLKEM768']['nistQuantumSecurityLevel'] == 3


def test_symmetric_cipher_primitive_and_mode(document):
    algos = {
        a['name']: a['cryptoProperties']['algorithmProperties']
        for a in _by_type(document)['algorithm']
    }
    assert algos['AES256-GCM']['primitive'] == 'block-cipher'
    assert algos['AES256-GCM']['mode'] == 'gcm'
    assert algos['CHACHA20']['primitive'] == 'stream-cipher'
    assert 'mode' not in algos['CHACHA20']


def test_certificate_cross_references_resolve(document):
    refs = {c['bom-ref'] for c in document['components']}
    cert = _by_type(document)['certificate'][0]['cryptoProperties']['certificateProperties']
    assert cert['subjectName'] == 'localhost'
    assert cert['certificateFormat'] == 'X.509'
    # Refs must point at components that actually exist in the BOM.
    assert cert['signatureAlgorithmRef'] in refs
    assert cert['subjectPublicKeyRef'] in refs


def test_public_key_material(document):
    pub = (
        _by_type(document)['related-crypto-material'][0]
        ['cryptoProperties']['relatedCryptoMaterialProperties']
    )
    assert pub['type'] == 'public-key'
    assert pub['size'] == 2048
    assert pub['algorithmRef'] in {c['bom-ref'] for c in document['components']}


def test_non_crypto_sections_excluded(document):
    # testssl vulnerabilities / rating must not leak into the CBOM inventory.
    names = {c['name'].lower() for c in document['components']}
    assert not {'heartbleed', 'robot', 'rating', 'overall_grade'} & names


def test_document_is_valid_cyclonedx_16(document):
    from cyclonedx.validation.json import JsonStrictValidator
    from cyclonedx.schema import SchemaVersion
    errors = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(document))
    assert errors is None


def test_build_sets_version_and_scan_id():
    scan = m.Scan(result={'scanResult': []}, scanner=m.Scanner.testssl, id=7)
    rec = cbom.build(scan)
    assert rec.builder_version == cbom.BUILDER_VERSION
    assert rec.scan_id == 7


def test_ssh_audit_scanner_is_supported():
    # Both scanners have builders now; an empty ssh result yields a valid
    # (near-empty) CBOM rather than raising.
    rec = cbom.build(m.Scan(result={}, scanner=m.Scanner.ssh_audit))
    assert rec.builder_version == cbom.BUILDER_VERSION
    assert rec.document['bomFormat'] == 'CycloneDX'


@pytest.mark.slow
async def test_build_cbom_from_real_testssl_scan(current_openssl_server):
    """End-to-end: a real testssl scan of the local openssl server -> valid CBOM."""
    from tlssec.core.testssl import Testssl

    ep = m.Endpoint(
        ip='127.0.0.1', hostname='localhost', port=4433,
        tls_mode=m.TlsMode.implicit,
    )
    scan = await Testssl().scan(ep)
    assert scan.scanner == m.Scanner.testssl

    document = cbom.build(scan).document
    types = {c['cryptoProperties']['assetType'] for c in document['components']}
    assert {'protocol', 'algorithm', 'certificate'} <= types

    from cyclonedx.validation.json import JsonStrictValidator
    from cyclonedx.schema import SchemaVersion
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(document)) is None
