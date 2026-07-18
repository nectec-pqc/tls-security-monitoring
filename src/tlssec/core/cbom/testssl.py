"""Build a CycloneDX 1.6 CBOM from a testssl.sh ``--json-pretty`` result.

The CBOM is a *factual* cryptographic inventory of an endpoint: the TLS
protocol versions and cipher suites it offers, the individual algorithms
(key-exchange / KEM, symmetric ciphers, signatures), and the leaf certificate
with its public key. Verdicts (weak/strong, quantum-safe, policy) are
intentionally NOT recorded here -- those belong to the opinion layer
(``tlssec.core.opinion``), because they change as standards evolve while these
facts do not.

Only the crypto-relevant testssl sections are consumed. ``vulnerabilities``,
``rating``, ``headerResponse`` and ``browserSimulations`` are deliberately left
for the raw scan / opinion layer.
"""
import re
from datetime import datetime

from cyclonedx.model.bom import Bom
from cyclonedx.model import crypto

import tlssec.standard as standard

from ._base import _CryptoBomBuilder, _slug


# testssl protocol id -> human TLS/SSL version string.
_PROTO_VERSION = {
    'SSLv2': 'SSL 2.0',
    'SSLv3': 'SSL 3.0',
    'TLS1': '1.0',
    'TLS1_1': '1.1',
    'TLS1_2': '1.2',
    'TLS1_3': '1.3',
}

# ML-KEM (and hybrids embedding it / Kyber) -> NIST PQC security category.
# This is an inherent design parameter of the algorithm, hence a CBOM fact.
_KEM_NIST_LEVEL = {
    'MLKEM512': 1, 'MLKEM768': 3, 'MLKEM1024': 5,
    'X25519MLKEM768': 3, 'SecP256r1MLKEM768': 3, 'SecP384r1MLKEM1024': 5,
    'curveSM2MLKEM768': 3,
    'X25519Kyber768Draft00': 3, 'SecP256r1Kyber768Draft00': 3,
}

def _by_id(items):
    """Index a testssl section (list of {id, finding, ...}) by id."""
    return {item['id']: item for item in items if 'id' in item}


def _hex_identifier(token: str) -> str | None:
    """'xc030' -> '0xC0,0x30' (two-byte IANA cipher-suite identifier)."""
    if not token.startswith('x'):
        return None
    hexdigits = token[1:]
    if len(hexdigits) % 2 or not re.fullmatch(r'[0-9a-fA-F]+', hexdigits):
        return None
    pairs = [hexdigits[i:i + 2].upper() for i in range(0, len(hexdigits), 2)]
    return ','.join(f'0x{p}' for p in pairs)


def _symmetric(openssl_name: str):
    """Return (name, primitive, mode) for the symmetric cipher, or None."""
    sym = standard.tls.guess_symenc_from_openssl_cipher_name(openssl_name)
    if sym is None:
        return None
    upper = openssl_name.upper()
    if sym in ('CHACHA20', 'RC4'):
        return sym, crypto.CryptoPrimitive.STREAM_CIPHER, None
    if 'GCM' in upper:
        mode = crypto.CryptoMode.GCM
    elif 'CCM' in upper:
        mode = crypto.CryptoMode.CCM
    else:
        mode = crypto.CryptoMode.CBC
    name = f'{sym}-{mode.value.upper()}' if mode else sym
    return name, crypto.CryptoPrimitive.BLOCK_CIPHER, mode


def _parse_datetime(finding: str):
    """testssl cert dates look like '2026-06-11 11:05'."""
    try:
        return datetime.strptime(finding.strip(), '%Y-%m-%d %H:%M')
    except (ValueError, AttributeError):
        return None


class _Builder(_CryptoBomBuilder):
    """Maps a testssl ``--json-pretty`` result into crypto-asset components."""

    def build(self, result: dict) -> Bom:
        if isinstance(result, dict):
            for entry in result.get('scanResult', []):
                self._add_entry(entry)
        return self.bom

    # -- per-host --------------------------------------------------------

    def _add_entry(self, entry: dict):
        host = entry.get('targetHost') or entry.get('ip') or 'host'
        self._add_algorithms(entry.get('fs', []))
        self._add_protocols(entry, host)
        self._add_certificate(entry, host)

    def _add_algorithms(self, fs_items):
        fs = _by_id(fs_items)

        for curve in _findings(fs.get('FS_ECDHE_curves')):
            self.algorithm(curve, crypto.CryptoPrimitive.KEY_AGREE, curve=curve)
        for group in _findings(fs.get('DH_groups')):
            self.algorithm(group, crypto.CryptoPrimitive.KEY_AGREE)
        for kem in _findings(fs.get('FS_KEMs')):
            self.algorithm(
                kem, crypto.CryptoPrimitive.KEM,
                nist=_KEM_NIST_LEVEL.get(kem),
            )
        for sig in _findings(fs.get('FS_TLS13_sig_algs')) + _findings(fs.get('FS_TLS12_sig_algs')):
            self.algorithm(sig, crypto.CryptoPrimitive.SIGNATURE)
        for cipher in _findings(fs.get('FS_ciphers')):
            sym = _symmetric(cipher)
            if sym is not None:
                name, primitive, mode = sym
                self.algorithm(name, primitive, mode=mode)

    def _add_protocols(self, entry, host):
        protocols = _by_id(entry.get('protocols', []))
        suites_by_version = self._cipher_suites_by_version(entry.get('serverPreferences', []))

        for proto_id, version in _PROTO_VERSION.items():
            item = protocols.get(proto_id)
            if item is None or not str(item.get('finding', '')).startswith('offered'):
                continue
            self._add(
                f'proto-{_slug(host)}-tls-{_slug(version)}',
                f'TLS {version}' if not version.startswith('SSL') else version,
                crypto.CryptoProperties(
                    asset_type=crypto.CryptoAssetType.PROTOCOL,
                    protocol_properties=crypto.ProtocolProperties(
                        type=crypto.ProtocolPropertiesType.TLS,
                        version=version,
                        cipher_suites=suites_by_version.get(version, []),
                    ),
                ),
            )

    def _cipher_suites_by_version(self, server_preferences):
        by_version: dict[str, list] = {}
        for item in server_preferences:
            parts = str(item.get('finding', '')).split()
            # Columnar cipher line: <TLSvX.Y> <xHEX> <openssl> ... <IANA_NAME>
            if len(parts) < 7 or not parts[-1].startswith('TLS_'):
                continue
            identifier = _hex_identifier(parts[1])
            if identifier is None:
                continue
            version = parts[0].replace('TLSv', '')
            algorithms = []
            sym = _symmetric(parts[2])
            if sym is not None:
                algorithms.append(self.algorithm(sym[0], sym[1], mode=sym[2]).bom_ref)
            by_version.setdefault(version, []).append(
                crypto.ProtocolPropertiesCipherSuite(
                    name=parts[-1],
                    identifiers=[identifier],
                    algorithms=algorithms,
                )
            )
        return by_version

    def _add_certificate(self, entry, host):
        sd = _by_id(entry.get('serverDefaults', []))
        if 'cert_signatureAlgorithm' not in sd and 'cert_keySize' not in sd:
            return

        sig_ref = None
        if (sig := _finding(sd.get('cert_signatureAlgorithm'))):
            sig_ref = self.algorithm(sig, crypto.CryptoPrimitive.SIGNATURE).bom_ref

        key_ref = None
        if (keysize := _finding(sd.get('cert_keySize'))):
            key_ref = self._add_public_key(keysize, host)

        fingerprint = _finding(sd.get('cert_fingerprintSHA256')) or _finding(sd.get('cert_commonName')) or host
        self._add(
            f'cert-{_slug(host)}-{_slug(fingerprint)}',
            _finding(sd.get('cert_commonName')) or f'certificate {host}',
            crypto.CryptoProperties(
                asset_type=crypto.CryptoAssetType.CERTIFICATE,
                certificate_properties=crypto.CertificateProperties(
                    subject_name=_finding(sd.get('cert_commonName')),
                    issuer_name=_finding(sd.get('cert_caIssuers')),
                    not_valid_before=_parse_datetime(_finding(sd.get('cert_notBefore'))),
                    not_valid_after=_parse_datetime(_finding(sd.get('cert_notAfter'))),
                    signature_algorithm_ref=sig_ref,
                    subject_public_key_ref=key_ref,
                    certificate_format='X.509',
                ),
            ),
        )

    def _add_public_key(self, keysize_finding, host):
        # e.g. 'RSA 2048 bits (exponent is 65537)'
        match = re.match(r'\s*([A-Za-z0-9]+)\s+(\d+)\s*bits', keysize_finding)
        algo_name = match.group(1) if match else keysize_finding.split()[0]
        size = int(match.group(2)) if match else None
        algo_ref = self.algorithm(algo_name, crypto.CryptoPrimitive.PKE).bom_ref
        comp = self._add(
            f'key-{_slug(host)}-{_slug(algo_name)}-{size}',
            f'{algo_name} public key',
            crypto.CryptoProperties(
                asset_type=crypto.CryptoAssetType.RELATED_CRYPTO_MATERIAL,
                related_crypto_material_properties=crypto.RelatedCryptoMaterialProperties(
                    type=crypto.RelatedCryptoMaterialType.PUBLIC_KEY,
                    size=size,
                    algorithm_ref=algo_ref,
                ),
            ),
        )
        return comp.bom_ref


def _finding(item):
    return item.get('finding') if item else None


def _findings(item):
    """Split a space-separated testssl finding into tokens (empty if absent)."""
    finding = _finding(item)
    return finding.split() if finding else []


def build_bom_from_testssl(result: dict) -> Bom:
    """Build a CycloneDX 1.6 Bom of cryptographic assets from a testssl result."""
    return _Builder().build(result)
