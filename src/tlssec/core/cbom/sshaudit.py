"""Build a CycloneDX 2.6 CBOM from an ``ssh-audit --json`` result.

SSH has no TLS-style cipher suites; it negotiates independent lists of
key-exchange, host-key, cipher and MAC algorithms. Each becomes an individual
``algorithm`` asset, and the single ``protocol`` asset (type ``ssh``) links
them via ``protocolProperties.cryptoRefArray``. Host-key fingerprints become
``related-crypto-material`` digests.

As with the testssl builder this is facts only; ssh-audit's fail/warn notes,
CVEs and recommendations are left for the opinion layer.
"""
from cyclonedx.model.bom import Bom
from cyclonedx.model import crypto

from ._base import _CryptoBomBuilder, _slug

# PQC key-exchange families -> NIST security category (matched as a substring
# of the ssh algorithm name, e.g. 'mlkem768x25519-sha256').
_KEM_NIST_LEVEL = {
    'mlkem1024': 5, 'mlkem768': 3, 'mlkem512': 1,
    'sntrup761': 2, 'sntrup4591761': 2,
    'kyber-1024': 5, 'kyber-768': 3, 'kyber-512': 1,
}

# ssh-audit lists these protocol-extension markers among "kex"; they are not
# cryptographic algorithms.
_KEX_PSEUDO_PREFIXES = ('ext-info-', 'kex-strict-')


class _Builder(_CryptoBomBuilder):
    """Maps an ssh-audit result into crypto-asset components."""

    def build(self, result: dict) -> Bom:
        if not isinstance(result, dict):
            return self.bom

        refs = []

        def add(comp):
            if comp is not None:
                refs.append(comp.bom_ref)

        for item in result.get('kex', []):
            add(self._kex(item.get('algorithm')))
        for item in result.get('key', []):
            if name := item.get('algorithm'):
                add(self.algorithm(name, crypto.CryptoPrimitive.SIGNATURE))
        for item in result.get('enc', []):
            add(self._enc(item.get('algorithm')))
        for item in result.get('mac', []):
            if name := item.get('algorithm'):
                add(self.algorithm(name, crypto.CryptoPrimitive.MAC))

        self._fingerprints(result.get('fingerprints', []))
        self._protocol(result.get('banner', {}), result.get('target'), refs)
        return self.bom

    def _kex(self, name):
        if not name or name.startswith(_KEX_PSEUDO_PREFIXES):
            return None
        low = name.lower()
        for token, level in _KEM_NIST_LEVEL.items():
            if token in low:
                return self.algorithm(name, crypto.CryptoPrimitive.KEM, nist=level)
        return self.algorithm(name, crypto.CryptoPrimitive.KEY_AGREE)

    def _enc(self, name):
        if not name:
            return None
        base = name.split('@')[0].lower()
        if base.startswith('chacha20'):
            return self.algorithm(name, crypto.CryptoPrimitive.STREAM_CIPHER)
        if 'gcm' in base:
            mode = crypto.CryptoMode.GCM
        elif 'ctr' in base:
            mode = crypto.CryptoMode.CTR
        elif 'cbc' in base:
            mode = crypto.CryptoMode.CBC
        else:
            mode = None
        return self.algorithm(name, crypto.CryptoPrimitive.BLOCK_CIPHER, mode=mode)

    def _fingerprints(self, fingerprints):
        for fp in fingerprints:
            hostkey = fp.get('hostkey', 'hostkey')
            hash_alg = fp.get('hash_alg', 'hash')
            self._add(
                f'digest-{_slug(hostkey)}-{_slug(hash_alg)}',
                f'{hostkey} {hash_alg} fingerprint',
                crypto.CryptoProperties(
                    asset_type=crypto.CryptoAssetType.RELATED_CRYPTO_MATERIAL,
                    related_crypto_material_properties=crypto.RelatedCryptoMaterialProperties(
                        type=crypto.RelatedCryptoMaterialType.DIGEST,
                        format=hash_alg,
                        value=fp.get('hash'),
                    ),
                ),
            )

    def _protocol(self, banner, target, refs):
        version = (banner or {}).get('protocol') or 'unknown'
        software = (banner or {}).get('software')
        # De-duplicate refs while preserving order.
        crypto_refs = list({ref.value: ref for ref in refs}.values())
        self._add(
            f'proto-ssh-{_slug(target or "host")}',
            software or f'SSH {version}',
            crypto.CryptoProperties(
                asset_type=crypto.CryptoAssetType.PROTOCOL,
                protocol_properties=crypto.ProtocolProperties(
                    type=crypto.ProtocolPropertiesType.SSH,
                    version=version,
                    crypto_refs=crypto_refs,
                ),
            ),
        )


def build_bom_from_sshaudit(result: dict) -> Bom:
    """Build a CycloneDX 1.6 Bom of cryptographic assets from an ssh-audit result."""
    return _Builder().build(result)
