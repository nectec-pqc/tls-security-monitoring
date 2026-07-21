"""Layer 3: derive a verdict from a CBOM (and capture vendor verdicts).

An opinion is judgment, not fact: quantum-safety, weak protocol/cipher, and
certificate health, computed from the Layer-2 CBOM inventory. Because these
change as standards evolve, opinions are re-derivable and versioned by
``RULESET_VERSION`` -- bump it when the rules below change.

Our own assessment is derived from the CBOM alone (proving the CBOM is a
sufficient basis for verdicts). Vendor verdicts already present in the raw
scan (testssl ``rating`` / ``vulnerabilities``) are captured alongside it.
"""
from datetime import datetime, timezone

import tlssec.core.model as m
import tlssec.standard as standard

RULESET_VERSION = '0.2.0'

_WEAK_PROTOCOL_VERSIONS = {'SSL 2.0', 'SSL 3.0', '1.0', '1.1'}
_WEAK_SYMENC = {'RC4', '3DES', 'DES', 'NULL'}


def derive(cbom: m.Cbom, scan: m.Scan | m.ScanTable) -> m.Opinion:
    """Derive an opinion from a CBOM plus the raw scan it came from."""
    document = cbom.document
    verdict = {
        'quantum': _quantum(document),
        'weakness': _weakness(document),
        'certificate': _certificate(document),
        'vendor': _vendor(scan),
    }
    return m.Opinion(
        cbom_id=getattr(cbom, 'id', None),
        ruleset_version=RULESET_VERSION,
        verdict=verdict,
    )


# --- our assessment, from CBOM facts ---------------------------------------

def _algorithms(document):
    for comp in document.get('components', []):
        cp = comp.get('cryptoProperties', {})
        if cp.get('assetType') == 'algorithm':
            yield comp['name'], cp.get('algorithmProperties', {})


def _protocol_versions(document):
    return [
        comp['cryptoProperties']['protocolProperties'].get('version')
        for comp in document.get('components', [])
        if comp.get('cryptoProperties', {}).get('assetType') == 'protocol'
    ]


def _symenc_base(name: str) -> str:
    # Normalize a symmetric algorithm name to its testssl-style base token:
    # 'AES256-GCM' -> 'AES256', 'aes256-gcm@openssh.com' -> 'AES256'.
    return name.split('@')[0].split('-')[0].upper()


def _is_pqc(ap) -> bool:
    """PQC iff the CBOM tagged a NIST category, which is scanner-agnostic."""
    nist = ap.get('nistQuantumSecurityLevel')
    return nist is not None and nist >= 1


def _quantum(document):
    safe_kex, unsafe_kex, safe_sym, unsafe_sym = set(), set(), set(), set()
    safe_sig, unsafe_sig = set(), set()
    for name, ap in _algorithms(document):
        primitive = ap.get('primitive')
        if primitive in ('kem', 'key-agree'):
            (safe_kex if _is_pqc(ap) else unsafe_kex).add(name)
        elif primitive in ('block-cipher', 'stream-cipher'):
            is_safe = standard.tls.IS_SYMENC_QUANTUM_SAFE.get(_symenc_base(name))
            (safe_sym if is_safe else unsafe_sym).add(name)
        elif primitive == 'signature':
            (safe_sig if _is_pqc(ap) else unsafe_sig).add(name)
    return {
        # PQC-capable: offers at least one quantum-safe key establishment.
        'pqc_capable': bool(safe_kex),
        # Overall safe requires PQC key establishment AND no quantum-weak symmetric.
        # Signatures are deliberately excluded: key establishment is exposed to
        # harvest-now-decrypt-later, while a signature only enables live
        # impersonation and cannot be forged retroactively.
        'quantum_safe': bool(safe_kex) and not unsafe_sym,
        'safe_key_establishment': sorted(safe_kex),
        'unsafe_key_establishment': sorted(unsafe_kex),
        'safe_symmetric': sorted(safe_sym),
        'unsafe_symmetric': sorted(unsafe_sym),
        # Authentication axis, reported separately from `quantum_safe`.
        'pqc_signature': bool(safe_sig),
        'safe_signature': sorted(safe_sig),
        'unsafe_signature': sorted(unsafe_sig),
    }


def _weakness(document):
    weak_protocols = [v for v in _protocol_versions(document) if v in _WEAK_PROTOCOL_VERSIONS]
    weak_ciphers = sorted({
        name
        for name, ap in _algorithms(document)
        if ap.get('primitive') in ('block-cipher', 'stream-cipher')
        and _symenc_base(name) in _WEAK_SYMENC
    })
    return {
        'weak_protocols': sorted(set(weak_protocols)),
        'weak_ciphers': weak_ciphers,
        'is_weak': bool(weak_protocols or weak_ciphers),
    }


def _certificate(document):
    certs = [
        comp['cryptoProperties']['certificateProperties']
        for comp in document.get('components', [])
        if comp.get('cryptoProperties', {}).get('assetType') == 'certificate'
    ]
    if not certs:
        return None
    cert = certs[0]
    not_after = cert.get('notValidAfter')
    expired = None
    if not_after:
        try:
            expired = datetime.fromisoformat(not_after) < datetime.now(timezone.utc)
        except ValueError:
            expired = None
    subject, issuer = cert.get('subjectName'), cert.get('issuerName')
    return {
        'expires': not_after,
        'expired': expired,
        'self_signed': subject is not None and subject == issuer,
    }


# --- captured vendor verdicts, from the raw scan ---------------------------

def _by_id(items):
    return {item['id']: item for item in items if 'id' in item}


def _vendor(scan: m.Scan | m.ScanTable):
    scanner = m.Scanner(scan.scanner)
    result = scan.result if isinstance(scan.result, dict) else {}
    if scanner == m.Scanner.testssl:
        return _vendor_testssl(result)
    if scanner == m.Scanner.ssh_audit:
        return _vendor_sshaudit(result)
    return {}


def _vendor_testssl(result):
    entries = result.get('scanResult', [])
    if not entries:
        return {'tool': 'testssl'}
    entry = entries[0]
    rating = _by_id(entry.get('rating', []))
    flagged = [
        {'id': v['id'], 'severity': v.get('severity'), 'finding': v.get('finding')}
        for v in entry.get('vulnerabilities', [])
        if v.get('severity') not in ('OK', 'INFO', None)
    ]
    return {
        'tool': 'testssl',
        'grade': (rating.get('overall_grade') or {}).get('finding'),
        'score': (rating.get('final_score') or {}).get('finding'),
        'vulnerabilities': flagged,
    }


def _vendor_sshaudit(result):
    flagged = []
    for section in ('kex', 'key', 'enc', 'mac'):
        for item in result.get(section, []):
            notes = item.get('notes', {})
            if notes.get('fail') or notes.get('warn'):
                flagged.append({
                    'section': section,
                    'algorithm': item.get('algorithm'),
                    'fail': notes.get('fail', []),
                    'warn': notes.get('warn', []),
                })
    return {
        'tool': 'ssh-audit',
        'software': (result.get('banner') or {}).get('software'),
        'flagged': flagged,
        'cves': result.get('cves', []),
        'recommendations': result.get('recommendations', {}),
    }
