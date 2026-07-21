"""Layer 2: build CycloneDX 1.6 CBOM documents from raw scans.

A CBOM is a pure function of a raw scan's ``result`` and its ``scanner``, so it
can always be rebuilt. ``BUILDER_VERSION`` is stored alongside each CBOM so a
backfill can rebuild only what is missing *or* stale (built by an older
builder). Bump it whenever the mapping below changes in a way that should
invalidate previously built CBOMs.
"""
import json

from cyclonedx.model.bom import Bom
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion

import tlssec.core.model as m
from .testssl import build_bom_from_testssl
from .sshaudit import build_bom_from_sshaudit

BUILDER_VERSION = '0.2.0'

_BUILDERS = {
    m.Scanner.testssl: build_bom_from_testssl,
    m.Scanner.ssh_audit: build_bom_from_sshaudit,
}


def bom_to_document(bom: Bom) -> dict:
    """Serialize a Bom to a CycloneDX 1.6 JSON dict suitable for JSONB storage."""
    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6)
    return json.loads(outputter.output_as_string())


def build_bom(scan: m.Scan | m.ScanTable) -> Bom:
    """Build the in-memory CycloneDX Bom for a raw scan."""
    scanner = m.Scanner(scan.scanner)
    builder = _BUILDERS.get(scanner)
    if builder is None:
        raise NotImplementedError(f'no CBOM builder for scanner {scanner.value!r}')
    return builder(scan.result)


def build(scan: m.Scan | m.ScanTable) -> m.Cbom:
    """Build a CBOM record (document + builder version) from a raw scan."""
    return m.Cbom(
        scan_id=getattr(scan, 'id', None),
        builder_version=BUILDER_VERSION,
        document=bom_to_document(build_bom(scan)),
    )
