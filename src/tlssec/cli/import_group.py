import logging
_logger = logging.getLogger(__name__)
from pathlib import Path

import click

import tlssec.core.model as model
import tlssec.core.operation as op
from .cli_state import CliState


@click.group(name = 'import')
def import_group():
    """Add objects to tlssec database"""
    pass


@import_group.command()
@click.argument(
    'paths',
    metavar = 'files',
    type = click.Path(
        exists = True,
        dir_okay = False,
        path_type = Path,
    ),
    nargs = -1,
)
@click.pass_context
def scan(
    ctx,
    paths: list[Path],
):
    """Import scan result from externally executed scans into tlssec database

    Files can be either in JSON or YAML format.
    They can be produced from either

    \b
    - `testssl.sh --json` or
    - `testssl.sh --json-pretty`
    """
    if not paths:
        _logger.warn('No paths given to import scans from')
        return
    state = ctx.find_object(CliState)
    fails = []
    # NOTE: If slow, try batch commit.
    for path in paths:
        _logger.info(f'importing scan from {path}')
        try:
            scan = model.Scan.from_file(path)
            op.import_scan(scan, session = state.db.session)
            state.db.session.commit()
        except Exception as e:
            _logger.exception(f'Failed to import scan from {path}')
            fails.append(path)
    if fails:
        _logger.error(f'import failed on {len(fails)} paths')
        ctx.exit(1)
