import logging
_logger = logging.getLogger(__name__)

from sqlmodel import Session

import tlssec.core.model as model


def import_scan(
    scan: model.Scan,
    *,
    session: Session,
):
    if not isinstance(scan, model.ScanTable):
        scan = model.ScanTable(**scan.model_dump(exclude = ['id']))
    session.add(scan)
