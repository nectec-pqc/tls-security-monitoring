import logging
_logger = logging.getLogger(__name__)
from pathlib import Path

import click
import yaml

from tlssec.settings import Settings
from tlssec.database.database import Database
import tlssec.core.model as model
import tlssec.core.operation as op
from .cli_state import CliState


@click.group('tlssec')
@click.option(
    '--config', 'config_file',
    default = None,
    type = click.File('r'),
    help = 'Override configurations with values from JSON or YAML file',
)
@click.pass_context
def cli(ctx, config_file):
    """TLS security monitoring toolkit"""
    state = ctx.ensure_object(CliState)
    if config_file:
        setting_overrides = yaml.safe_load(config_file)
    else:
        setting_overrides = {}
    state.settings = Settings(**setting_overrides)
    state.db = Database(state.settings)
    ctx.with_resource(state.db.session)

    logging.basicConfig(
        format = '%(asctime)s %(name)s %(levelname)s: %(message)s',
        level = logging.INFO,
    )
    if state.settings.deployment_mode == 'development':
        logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)


@cli.command()
@click.option(
    '--reset',
    is_flag = True,
    help = 'Discard existing tables first.',
)
@click.pass_context
def init(ctx, reset):
    """Initialize database"""
    state = ctx.find_object(CliState)
    if reset:
        op.drop_database(state.db.engine)
    op.initialize_database(state.db.engine)


@cli.group()
def show():
    """Show system status"""
    pass


@show.command(name = 'settings')
@click.pass_context
def show_settings(ctx):
    """Show effective settings.

    (after merging defaults, environment variable, cli options together.)
    """
    state = ctx.find_object(CliState)
    print(state.settings.model_dump_json(indent = 2))


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
    # NOTE: If slow, try batch commit.
    for path in paths:
        _logger.info(f'importing scan from {path}')
        try:
            scan = model.ScanTable.from_file(path)
            op.import_scan(scan, session = state.db.session)
            state.db.session.commit()
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
