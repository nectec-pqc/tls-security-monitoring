import logging
_logger = logging.getLogger(__name__)

import asyncio
import json
from pathlib import Path
from datetime import datetime

import click
import yaml
from pydantic import ValidationError

from tlssec.settings import Settings
from tlssec.database.database import Database
import tlssec.core.model as model
import tlssec.core.operation as op
from .colored_help import ColoredGroup, ColoredCommand
from .cli_state import CliState
from .import_group import import_group
from .adhoc import adhoc
from tlssec.core.nmap import Nmap
from tlssec.core.testssl import Testssl
from tlssec.core.sshaudit import SshAudit


@click.group(
    'tlssec',
    cls = ColoredGroup,
)
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


@cli.command(cls = ColoredCommand)
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


@cli.group(cls = ColoredGroup)
def show():
    """Show system status"""
    pass


@show.command(
    name = 'settings',
    cls = ColoredCommand,
)
@click.pass_context
def show_settings(ctx):
    """Show effective settings.

    (after merging defaults, environment variable, cli options together.)
    """
    state = ctx.find_object(CliState)
    print(state.settings.model_dump_json(indent=2))


@cli.command(cls = ColoredCommand)
@click.option('--id', 'ids', multiple=True, type=int, help='Select endpoint by id')
@click.option('--tag', 'tags', multiple=True, help='Select endpoints carrying ALL of these tag path(s)')
@click.option('--ip', 'ips', multiple=True, help='Select endpoints by IP address')
@click.option('--hostname', 'hostnames', multiple=True, help='Select endpoints by hostname')
@click.option('--port', type=int, default=None, help='Select endpoints by port')
@click.option('--force', '-f', is_flag=True, help='Scan even if within the cooldown window')
@click.option('--no-cbom', is_flag=True, help='Only store the raw scan; skip building CBOM and opinion')
@click.option('--no-opinion', is_flag=True, help='Build the CBOM but skip the opinion layer')
@click.pass_context
def scan(ctx, ids, tags, ips, hostnames, port, force, no_cbom, no_opinion):
    """Scan endpoints and record the results.

    With no selection options every active endpoint in the system is scanned.
    Narrow the target set with --id, --tag, --ip, --hostname and/or --port using
    the same intersection semantics as `edit endpoint` and `delete endpoint`:
    all given criteria must match (so adding options narrows toward a single
    endpoint), while repeating one option (e.g. two --ip) matches any of those
    values. Disabled (retired) endpoints are always skipped.

    Endpoints scanned more recently than the configured cooldown
    (TLSSEC_ENDPOINT_COOLDOWN, default 7 days) are skipped so repeated runs only
    re-scan what is due; pass --force to scan them anyway. Retiring is separate:
    --force does not scan retired endpoints (re-enable them with `edit endpoint
    --enable`).

    Each recorded raw scan is normalized into a CycloneDX CBOM and an opinion
    by default; use --no-cbom / --no-opinion to store the raw scan only.
    """
    state = ctx.find_object(CliState)
    session = state.db.session

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

    # One timestamp for the whole run: the cooldown cutoff reference and the
    # last_seen stamp written to every scanned endpoint below.
    now = datetime.now()

    scannable = [ep for ep in endpoints if ep.retire_at is None]
    if force:
        in_cooldown = 0
    else:
        cooldown = state.settings.endpoint_cooldown
        due = [ep for ep in scannable if not op.is_in_cooldown(ep, cooldown, now)]
        in_cooldown = len(scannable) - len(due)
        scannable = due

    if not scannable:
        if in_cooldown:
            click.echo(
                f'All {in_cooldown} matched endpoint(s) are within the cooldown'
                f' window; use --force to scan anyway.'
            )
        else:
            click.echo('No endpoints to scan.')
        return

    message = f'Scanning {len(scannable)} endpoint(s)...'
    if in_cooldown:
        message += f' ({in_cooldown} skipped: in cooldown)'
    click.echo(message)

    testssl = Testssl()
    sshaudit = SshAudit()

    def scanner_for(ep):
        # SSH endpoints are scanned with ssh-audit; everything else with testssl.
        if (ep.application_protocol or '').lower() == 'ssh':
            return sshaudit
        return testssl

    async def run_all():
        return await asyncio.gather(*(
            scanner_for(ep).scan(model.Endpoint.model_validate(ep))
            for ep in scannable
        ), return_exceptions=True)

    results = asyncio.run(run_all())

    recorded = 0
    failed = 0
    built = 0
    for ep, result in zip(scannable, results):
        label = f'{ep.ip or ep.hostname}:{ep.port}'
        # One endpoint failing (unreachable host, testssl error, ...) must not
        # discard the scans that did succeed.
        if isinstance(result, Exception):
            failed += 1
            click.echo(f'  failed {label}: {result}')
            continue
        scan_row = model.ScanTable(
            result=result.result,
            scanner=result.scanner,
            scanner_version=result.scanner_version,
            observed_ip=result.observed_ip,
            sni=result.sni,
            start_time=result.start_time,
            time_taken=result.time_taken,
            belong_to_endpoint_id=ep.id,
        )
        session.add(scan_row)
        # last_seen is the scheduling clock read by the cooldown filter above;
        # stamp it whenever a raw scan is recorded (independent of CBOM success).
        ep.last_seen = now
        recorded += 1
        click.echo(f'  scanned {label}')

        # Normalize into CBOM (+ opinion) by default. A build failure must not
        # lose the raw scan, which is the only irreproducible artifact.
        if not no_cbom:
            session.flush()  # assign scan_row.id for the FK
            try:
                op.store_cbom_for_scan(session, scan_row, with_opinion=not no_opinion)
                built += 1
            except Exception as e:
                click.echo(f'  cbom failed {label}: {e}')

    session.commit()
    summary = f'Done. Recorded {recorded} scan(s)'
    if not no_cbom:
        summary += f'; built {built} CBOM(s)'
    if failed:
        summary += f'; {failed} failed'
    click.echo(summary + '.')


# --- view: read back stored raw / CBOM / opinion layers --------------------

_VIEW_LAYERS = ('raw', 'cbom', 'opinion')


def _safe_component(text):
    """Filesystem-safe slug: keep alnum and . _ + - ; replace the rest with _."""
    return ''.join(c if (c.isalnum() or c in '._+-') else '_' for c in text) or 'all'


def _selection_slug(ids, tags, ips, hostnames, port):
    """Name outputs after *what was used to select* the endpoints.

    e.g. ``hostname-100m.forest.go.th``, ``id-1+port-443``, or ``all`` when no
    selector was given.
    """
    parts = []
    for label, values in (('id', ids), ('tag', tags), ('ip', ips), ('hostname', hostnames)):
        parts += [f'{label}-{v}' for v in values]
    if port is not None:
        parts.append(f'port-{port}')
    return _safe_component('+'.join(parts) if parts else 'all')


def _latest_opinion(scan):
    """Newest opinion (highest id) on the scan's CBOM, or None."""
    if scan.cbom is None or not scan.cbom.opinions:
        return None
    return max(scan.cbom.opinions, key=lambda o: o.id)


def _layer_payload(scan, layer):
    """The stored JSON for one layer of a scan, or None if it does not exist."""
    if layer == 'raw':
        return scan.result
    if layer == 'cbom':
        return scan.cbom.document if scan.cbom else None
    opinion_row = _latest_opinion(scan)
    return opinion_row.verdict if opinion_row else None


def _layer_created(scan, layer):
    """Create time of a layer, used for the filename; falls back to now."""
    if layer == 'raw':
        dt = scan.start_time
    elif layer == 'cbom':
        dt = scan.cbom.created_at if scan.cbom else None
    else:
        opinion_row = _latest_opinion(scan)
        dt = opinion_row.created_at if opinion_row else None
    dt = dt or datetime.now()
    return dt.replace(tzinfo=None) if dt.tzinfo else dt


def _unique_path(directory, base):
    """``<base>.json`` in ``directory``, suffixing ``_2``, ``_3``, ... on collision."""
    path = directory / f'{base}.json'
    n = 2
    while path.exists():
        path = directory / f'{base}_{n}.json'
        n += 1
    return path


@cli.command()
@click.option('--id', 'ids', multiple=True, type=int, help='Select endpoint by id')
@click.option('--tag', 'tags', multiple=True, help='Select endpoints carrying ALL of these tag path(s)')
@click.option('--ip', 'ips', multiple=True, help='Select endpoints by IP address')
@click.option('--hostname', 'hostnames', multiple=True, help='Select endpoints by hostname')
@click.option('--port', type=int, default=None, help='Select endpoints by port')
@click.option('--raw', 'want_raw', is_flag=True, help='Include the raw scan result (Layer 1)')
@click.option('--cbom', 'want_cbom', is_flag=True, help='Include the CBOM document (Layer 2)')
@click.option('--opinion', 'want_opinion', is_flag=True, help='Include the latest opinion verdict (Layer 3)')
@click.option('--output', '-o', is_flag=True, help='Write each layer to a JSON file in output_dir instead of printing')
@click.pass_context
def view(ctx, ids, tags, ips, hostnames, port, want_raw, want_cbom, want_opinion, output):
    """View stored raw scan / CBOM / opinion for selected endpoints.

    Endpoints are selected exactly like `scan`: --id/--tag/--ip/--hostname/--port
    are ANDed together (repeating one option ORs its values) and passing no
    selector selects every endpoint. For each selected endpoint every scan is
    emitted, newest first.

    Choose at least one layer with --raw / --cbom / --opinion. Without --output
    the JSON is printed; with --output each (scan, layer) is written to
    output_dir as <create-time>_<layer>_<selection>.json, e.g.
    2026-07-18T02-09-44_opinion_hostname-100m.forest.go.th.json
    """
    state = ctx.find_object(CliState)
    session = state.db.session

    layers = [name for name, want in zip(_VIEW_LAYERS, (want_raw, want_cbom, want_opinion)) if want]
    if not layers:
        raise click.UsageError('choose at least one of --raw / --cbom / --opinion')

    try:
        endpoints = op.select_endpoints(
            session,
            ids=list(ids), tag_paths=list(tags), ips=list(ips),
            hostnames=list(hostnames), port=port,
        )
    except ValueError as e:
        raise click.UsageError(str(e))

    if not endpoints:
        click.echo('No endpoints matched.')
        return

    slug = _selection_slug(ids, tags, ips, hostnames, port)
    out_dir = state.settings.output_dir
    if output:
        out_dir.mkdir(parents=True, exist_ok=True)

    emitted = 0
    missing = 0
    for ep in endpoints:
        label = f'{ep.ip or ep.hostname}:{ep.port}'
        # Newest scan first; start_time is naive (TIMESTAMP without tz).
        scans = sorted(ep.scans, key=lambda s: s.start_time or datetime.min, reverse=True)
        for scan_row in scans:
            for layer in layers:
                payload = _layer_payload(scan_row, layer)
                if payload is None:
                    missing += 1
                    click.echo(f'  {label} scan {scan_row.id}: no {layer}')
                    continue
                if output:
                    base = f'{_layer_created(scan_row, layer):%Y-%m-%dT%H-%M-%S}_{layer}_{slug}'
                    path = _unique_path(out_dir, base)
                    path.write_text(json.dumps(payload, indent=2, default=str))
                    click.echo(f'  wrote {path.name}')
                else:
                    click.echo(f'# {label}  scan {scan_row.id}  [{layer}]')
                    click.echo(json.dumps(payload, indent=2, default=str))
                    click.echo('')
                emitted += 1

    if output:
        message = f'Wrote {emitted} file(s) to {out_dir}'
        if missing:
            message += f'; {missing} layer(s) not built yet'
        click.echo(message + '.')
    elif emitted == 0:
        click.echo('Nothing to show: selected endpoint(s) have no matching layers yet.')


cli.add_command(import_group)
cli.add_command(adhoc)


@cli.group(cls = ColoredGroup)
def cbom():
    """Build and manage the CBOM / opinion layers."""
    pass


@cbom.command('build', cls = ColoredCommand)
@click.option('--no-opinion', is_flag=True, help='Backfill CBOMs but not opinions')
@click.pass_context
def cbom_build(ctx, no_opinion):
    """Backfill CBOMs (and opinions) for raw scans that lack a current one.

    Rebuilds any scan whose CBOM is missing or was built by an older builder
    version, then derives opinions for CBOMs missing a current-ruleset opinion.
    Safe to run repeatedly; it only touches what is missing or stale.
    """
    state = ctx.find_object(CliState)
    session = state.db.session
    n_cbom = op.backfill_cboms(session, with_opinion=not no_opinion)
    n_opinion = 0 if no_opinion else op.backfill_opinions(session)
    session.commit()
    message = f'Built {n_cbom} CBOM(s)'
    if not no_opinion:
        message += f'; {n_opinion} opinion(s)'
    click.echo(message + '.')


@cli.command(cls = ColoredCommand)
def report():
    """Produce report"""
    raise NotImplementedError


@cli.group(
    chain = True,
    cls = ColoredGroup,
)
@click.pass_context
def add(ctx):
    """Add objects to the database"""
    pass


@add.result_callback()
@click.pass_context
def add_commit(ctx, results, **kwargs):
    state = ctx.find_object(CliState)
    state.db.session.commit()


@add.command(cls = ColoredCommand)
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
            ep_model = model.Endpoint(**raw)
            # Reuse an existing endpoint with the same scan identity instead of
            # inserting a duplicate; either way merge in the tags.
            ep = op.find_endpoint_by_identity(
                session,
                ip=ep_model.ip,
                hostname=ep_model.hostname,
                port=ep_model.port,
                transport_protocol=ep_model.transport_protocol,
            )
            if ep is None:
                ep = model.EndpointTable(**ep_model.model_dump(exclude={'id'}))
                session.add(ep)
                session.flush()
            op.add_endpoint_tags(session, ep, list(tag) + tags)
    else:
        ep = op.make_endpoint(session, port, ip, hostname, list(tag))


@cli.group(
    chain = True,
    cls = ColoredGroup,
)
@click.pass_context
def edit(ctx):
    """Edit objects in the database"""
    pass


@edit.result_callback()
@click.pass_context
def edit_commit(ctx, results, **kwargs):
    state = ctx.find_object(CliState)
    state.db.session.commit()


@edit.command(cls = ColoredCommand)
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


@cli.group(
    chain = True,
    cls = ColoredGroup,
)
@click.pass_context
def delete(ctx):
    """Delete objects from the database"""
    pass


@delete.result_callback()
@click.pass_context
def delete_commit(ctx, results, **kwargs):
    state = ctx.find_object(CliState)
    state.db.session.commit()


@delete.command(cls = ColoredCommand)
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


@cli.command(cls = ColoredCommand)
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
