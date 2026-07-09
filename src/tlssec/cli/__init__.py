import logging
_logger = logging.getLogger(__name__)

import asyncio
import click
import yaml
from pydantic import ValidationError

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


@cli.group(chain=True)
@click.pass_context
def edit(ctx):
    """Edit objects in the database"""
    pass


@edit.result_callback()
@click.pass_context
def edit_commit(ctx, results, **kwargs):
    state = ctx.find_object(CliState)
    state.db.session.commit()


@edit.command()
@click.option('--id', 'ids', multiple=True, type=int, help='Select endpoint by id')
@click.option('--tag', 'tags', multiple=True, help='Select endpoints carrying ALL of these tag path(s)')
@click.option('--ip', 'ips', multiple=True, help='Select endpoints by IP address')
@click.option('--hostname', 'hostnames', multiple=True, help='Select endpoints by hostname')
@click.option('--port', type=int, default=None, help='Select endpoints by port')
@click.option('--add-tag', 'add_tags', multiple=True, help='Attach this tag to selected endpoints')
@click.option('--remove-tag', 'remove_tags', multiple=True, help='Detach this tag from selected endpoints')
@click.option(
    '--change-tag', 'change_tags',
    multiple=True, nargs=2,
    metavar='OLD NEW',
    help='Replace tag OLD with NEW on selected endpoints',
)
@click.option(
    '--disable/--enable', 'disabled',
    default=None,
    help='Disable (skip on scan) or re-enable selected endpoints',
)
@click.pass_context
def endpoint(ctx, ids, tags, ips, hostnames, port, add_tags, remove_tags, change_tags, disabled):
    """Edit endpoint(s): retag or toggle scan participation.

    Select endpoints with --id, --tag, --ip, --hostname and/or --port. All
    given criteria must match (intersection), so adding more options narrows
    the selection toward a single endpoint; repeating the same option (e.g.
    two --ip) matches any of those values. Then apply changes. Disabled
    endpoints are skipped by scans but keep their tags and history, so the
    disabled state is independent from last_seen used for scheduling.
    """
    state = ctx.find_object(CliState)
    session = state.db.session

    if not (ids or tags or ips or hostnames or port is not None):
        raise click.UsageError('select endpoints with --id, --tag, --ip, --hostname and/or --port')
    if not (add_tags or remove_tags or change_tags or disabled is not None):
        raise click.UsageError(
            'nothing to do: pass --add-tag/--remove-tag/--change-tag/--disable/--enable'
        )

    try:
        endpoints = op.select_endpoints(
            session,
            ids=list(ids),
            tag_paths=list(tags),
            ips=list(ips),
            hostnames=list(hostnames),
            port=port,
        )
    except ValueError as e:
        raise click.UsageError(str(e))

    if not endpoints:
        click.echo('No endpoints matched.')
        return

    try:
        for ep in endpoints:
            for old, new in change_tags:
                if not op.change_endpoint_tag(session, ep, old, new):
                    click.echo(
                        f'  endpoint {ep.id}: no tag "{old}", not adding "{new}"'
                    )
            for t in remove_tags:
                op.remove_endpoint_tag(session, ep, t)
            for t in add_tags:
                op.add_endpoint_tag(session, ep, t)
    except ValidationError as e:
        raise click.UsageError(f'invalid tag: {e}')

    if disabled is not None:
        op.set_endpoints_disabled(session, endpoints, disabled)

    action = 'Disabled' if disabled else 'Enabled' if disabled is False else 'Updated'
    click.echo(f'{action} {len(endpoints)} endpoint(s).')


@cli.group(chain=True)
@click.pass_context
def delete(ctx):
    """Delete objects from the database"""
    pass


@delete.result_callback()
@click.pass_context
def delete_commit(ctx, results, **kwargs):
    state = ctx.find_object(CliState)
    state.db.session.commit()


@delete.command()
@click.option('--id', 'ids', multiple=True, type=int, help='Select endpoint by id')
@click.option('--tag', 'tags', multiple=True, help='Select endpoints carrying ALL of these tag path(s)')
@click.option('--ip', 'ips', multiple=True, help='Select endpoints by IP address')
@click.option('--hostname', 'hostnames', multiple=True, help='Select endpoints by hostname')
@click.option('--port', type=int, default=None, help='Select endpoints by port')
@click.option('--yes', '-y', is_flag=True, help='Delete without confirmation prompt')
@click.pass_context
def endpoint(ctx, ids, tags, ips, hostnames, port, yes):
    """Delete endpoint(s) permanently.

    Select endpoints with --id, --tag, --ip, --hostname and/or --port using the
    same intersection semantics as `edit endpoint`: all given criteria must
    match, while repeating one option (e.g. two --ip) matches any of those
    values. Endpoints that carry scan history are not deleted but instead
    retired (disabled) so their history is preserved while they stop being
    scanned; history-free endpoints are removed outright.
    """
    state = ctx.find_object(CliState)
    session = state.db.session

    if not (ids or tags or ips or hostnames or port is not None):
        raise click.UsageError('select endpoints with --id, --tag, --ip, --hostname and/or --port')

    try:
        endpoints = op.select_endpoints(
            session,
            ids=list(ids),
            tag_paths=list(tags),
            ips=list(ips),
            hostnames=list(hostnames),
            port=port,
        )
    except ValueError as e:
        raise click.UsageError(str(e))

    if not endpoints:
        click.echo('No endpoints matched.')
        return

    deletable = [ep for ep in endpoints if not op.endpoint_has_scans(session, ep)]
    retire = [ep for ep in endpoints if ep not in deletable]

    for ep in retire:
        click.echo(f'  retiring {ep.id}: has scan history, disabling instead of deleting')

    if not deletable:
        if retire:
            op.set_endpoints_disabled(session, retire, True)
            click.echo(f'Retired {len(retire)} endpoint(s); deleted 0.')
        else:
            click.echo('Nothing to delete.')
        return

    if not yes:
        for ep in deletable:
            click.echo(f'  {ep.id}: {ep.ip or ep.hostname}:{ep.port}')
        if not click.confirm(f'Delete {len(deletable)} endpoint(s)?', default=False):
            click.echo('Aborted.')
            return

    op.delete_endpoints(session, deletable)
    if retire:
        op.set_endpoints_disabled(session, retire, True)
    click.echo(f'Deleted {len(deletable)} endpoint(s); retired {len(retire)}.')


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

    scannable = [ep for ep in existing if ep.retire_at is None]

    hosts = set()
    for ep in scannable:
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
