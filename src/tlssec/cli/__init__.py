import logging
_logger = logging.getLogger(__name__)
from pathlib import Path

import click
from sqlmodel import Session

from tlssec.settings import get_settings
from tlssec.database.engine import engine
from tlssec.database.init import initialize_database
import tlssec.core.model as model
import tlssec.core.operation as op
from .cli_state import CliState


@click.group('tlssec')
@click.pass_context
def cli(ctx):
    """TLS security monitoring toolkit"""
    logging.basicConfig(
        format = '%(asctime)s %(name)s %(levelname)s: %(message)s',
        level = logging.INFO,
    )
    if get_settings().deployment_mode == 'development':
        logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

    state = ctx.ensure_object(CliState)
    state.session = ctx.with_resource(Session(engine))


@cli.command()
def init():
    """Initialize database"""
    initialize_database()


@cli.command()
def status():
    """Check system status"""
    raise NotImplementedError


@cli.command()
def scan():
    """Start scanning"""
    raise NotImplementedError


@cli.command()
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
def import_scan(
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
    for path in paths:
        _logger.info(f'importing scan from {path}')
        try:
            scan = model.ScanTable.from_file(path)
            op.import_scan(scan, session = state.session)
            state.session.commit()
        except Exception as e:
            _logger.exception(f'Failed to import scan from {path}')
            fails.append(path)
    if fails:
        _logger.error(f'import failed on {len(fails)} paths')
        ctx.exit(1)


@cli.command()
def report():
    """Produce report"""
    raise NotImplementedError
