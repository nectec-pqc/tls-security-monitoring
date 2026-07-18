"""Shared machinery for building CycloneDX crypto-asset BOMs from scans.

Both the testssl and ssh-audit builders accumulate de-duplicated
``cryptographic-asset`` components into one :class:`Bom`; this base holds that
common plumbing so the per-scanner modules only express the mapping.
"""
import re

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model import crypto

_SLUG_RE = re.compile(r'[^a-z0-9]+')


def _slug(text: str) -> str:
    return _SLUG_RE.sub('-', text.lower()).strip('-')


class _CryptoBomBuilder:
    """Accumulates de-duplicated crypto-asset components into one Bom.

    Components are keyed by bom-ref so a shared algorithm referenced by several
    protocols / suites becomes a single asset that the others point at.
    """

    def __init__(self):
        self.bom = Bom()
        self._by_ref: dict[str, Component] = {}

    def _add(self, bom_ref, name, crypto_properties) -> Component:
        existing = self._by_ref.get(bom_ref)
        if existing is not None:
            return existing
        comp = Component(
            name=name,
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            bom_ref=bom_ref,
            crypto_properties=crypto_properties,
        )
        self.bom.components.add(comp)
        self._by_ref[bom_ref] = comp
        return comp

    def algorithm(self, name, primitive, *, curve=None, mode=None, nist=None) -> Component:
        return self._add(
            f'alg-{_slug(name)}',
            name,
            crypto.CryptoProperties(
                asset_type=crypto.CryptoAssetType.ALGORITHM,
                algorithm_properties=crypto.AlgorithmProperties(
                    primitive=primitive,
                    curve=curve,
                    mode=mode,
                    nist_quantum_security_level=nist,
                ),
            ),
        )
