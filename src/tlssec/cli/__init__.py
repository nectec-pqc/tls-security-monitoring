import logging
_logger = logging.getLogger(__name__)

import click
import yaml

from tlssec.settings import Settings
from tlssec.database.database import Database
import tlssec.core.model as model
import tlssec.core.operation as op
from .cli_state import CliState
from .import_group import import_group


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


cli.add_command(import_group)


@cli.command()
def report():
    """Produce report"""
    raise NotImplementedError
