import logging

from tlssec.core.model.service import Service
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

@cli.group(chain=True)
def add():
    """Add objects to the database"""
    pass

@add.command()
@click.pass_context()
def service_and_endpoint():
    pass

@add.command()
@click.option("--tag", multiple=True)
@click.option("--from_file", type=click.File("r"))
@click.option("--name_and_hostname", type=(str, str), help='Frist str is name and second str is hostname')
@click.pass_context
def service(ctx, tags, from_file, name_and_hostname):
    state = ctx.find_object(CliState)
    session = state.db.session
    if from_file and name_and_hostname:
        raise click.UsageError("use --from_file OR --name, not both")
    if not from_file and not name_and_hostname:
        raise click.UsageError("use --from_file OR --name")

    if from_file:
        services_and_tags = op.parse_service(from_file)
    else: 
        services_and_tags = op.make_service(name_and_hostname, tags) 

    # commit to DB 
    rows = []
    for service, tags in services_and_tags:
        row = model.ServiceTable(**service.model_dump(exclude={"id"}))
        session.add(row)    
        for tag in tags:
            leaf_tag = op.resolve_tag(session, tag)
            row.tags.append(leaf_tag)
        rows.append(row)
    state.services = rows
    session.commit()

@add.command()
@click.option()

@add.command()
@click.oprion("--from_file", type=click.File("r"))
@click.option("--name", "service_name")
@click.option("--port", type=int)
@click.option("--ip", type=str)
@click.option("--hostname", type=str)
@click.pass_context
def endpoint(ctx, from_file, service_name, port, ip, hostname):
    state = ctx.find_object(CliState)
    session = state.db.session 

    current_services = ctx.services


    if current_services: 
        # chain from add service  
        # if it have multiple service then we need to map endpoint to that service, but don't that mean  
        pass
    else: 
       # not chain from add service 
        if service_name and from_file:
            raise click.UsageError("use --from_file OR --name, not both")
        if not service_name and not from_file:
            raise click.UsageError("use --from_file OR --name")

        if from_file:
            op.parse_endpoint(session, from_file)
        else:
            op.make_endpoint(session, service_name, port, ip, hostname)

