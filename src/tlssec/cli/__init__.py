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
    default=None,
    type=click.File('r'),
    help='Override configurations with values from JSON or YAML file',
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
        format='%(asctime)s %(name)s %(levelname)s: %(message)s',
        level=logging.INFO,
    )
    if state.settings.deployment_mode == 'development':
        logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)


@cli.command()
@click.option(
    '--reset',
    is_flag=True,
    help='Discard existing tables first.',
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


@show.command(name='settings')
@click.pass_context
def show_settings(ctx):
    """Show effective settings.

    (after merging defaults, environment variable, cli options together.)
    """
    state = ctx.find_object(CliState)
    print(state.settings.model_dump_json(indent=2))


@cli.command()
def scan():
    """Start scanning"""
    raise NotImplementedError


cli.add_command(import_group)


@cli.command()
def report():
    """Produce report"""
    raise NotImplementedError


@cli.group(chain=True)
@click.pass_context
def add(ctx):
    """Add objects to the database"""
    pass


@add.result_callback()
@click.pass_context
def add_commit(ctx, results, **kwargs):
    state = ctx.find_object(CliState)
    state.db.session.commit()


@add.command()
@click.option('--tag', multiple=True, help='Tag path e.g. network/tls')
@click.option('--from_file', type=click.File('r'))
@click.option('--port', type=int, default=443)
@click.option('--ip', type=str, default=None)
@click.option('--hostname', type=str, default=None)
@click.pass_context
def endpoint(ctx, tag, from_file, port, ip, hostname):
    """Add an endpoint"""
    state = ctx.find_object(CliState)
    session = state.db.session

    if from_file and (ip or hostname):
        raise click.UsageError('use --from_file OR --ip/--hostname, not both')
    if not from_file and not ip and not hostname:
        raise click.UsageError('provide --from_file OR --ip/--hostname')

    if from_file:
        raw_endpoints = yaml.safe_load(from_file)
        for raw in raw_endpoints:
            tags = raw.pop('tags', [])
            ep = model.EndpointTable(**model.Endpoint(**raw).model_dump(exclude={'id'}))
            session.add(ep)
            session.flush()
            for t in list(tag) + tags:
                ep.tags.append(op.resolve_tag(session, t))
    else:
        ep = op.make_endpoint(session, port, ip, hostname, list(tag))
