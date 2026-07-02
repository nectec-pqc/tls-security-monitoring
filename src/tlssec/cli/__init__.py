import logging
_logger = logging.getLogger(__name__)

import asyncio
import click
import yaml

from tlssec.settings import Settings
from tlssec.database.database import Database
import tlssec.core.model as model
import tlssec.core.operation as op
from .cli_state import CliState
from .import_group import import_group
from tlssec.core.nmap import Nmap


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
    if not any([from_file, ip, hostname]):
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


@cli.command()
@click.option(
    '--tag',
    multiple = True,
    required = True,
    help = 'Exact tag path to select target endpoints e.g. network/tls',
)
@click.option(
    '--ports',
    default = None,
    help = 'Port range to scan e.g. 443,8443 or 1-1024 (default: all ports)',
)
@click.pass_context
def nmap(ctx, tag, ports):
    """Scan endpoints matching tag(s) with nmap and report new discoveries."""
    state = ctx.find_object(CliState)
    session = state.db.session

    existing = op.get_endpoints_by_tag(session, list(tag))
    if not existing:
        click.echo(f'No endpoints found with tags: {", ".join(tag)}')
        return

    hosts = set()
    for ep in existing:
        if ep.hostname:
            hosts.add(ep.hostname)
        elif ep.ip:
            hosts.add(str(ep.ip))

    if not hosts:
        click.echo('No scannable hosts found.')
        return

    click.echo(f'Scanning {len(hosts)} host(s): {", ".join(hosts)}')

    for host in hosts:
        _, discovered = asyncio.run(
            Nmap.discover_endpoints(
                host,
                ports = ports,
            )
        )

        new_endpoints = op.find_new_endpoints(discovered, existing)

        if not new_endpoints:
            click.echo(f'No new endpoints discovered on {host}.')
            continue

        click.echo(f'\nFound {len(new_endpoints)} new endpoint(s) on {host}:\n')

        for ep in new_endpoints:
            click.echo(
                f'  {ep.ip}:{ep.port}/{ep.transport_protocol}'
                f'  app={ep.application_protocol}'
                f'  tls={ep.tls_mode}'
                f'  hostname={ep.hostname}'
            )
            if click.confirm('  Add this endpoint?', default = True):
                row = model.EndpointTable(**ep.model_dump(exclude = {'id'}))
                session.add(row)
                session.flush()
                for t in tag:
                    row.tags.append(op.resolve_tag(session, t))

    session.commit()
    click.echo('\nDone.')
