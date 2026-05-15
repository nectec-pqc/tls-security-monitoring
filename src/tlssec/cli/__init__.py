import logging
_logger = logging.getLogger(__name__)

import click

from tlssec.settings import get_settings
from tlssec.database.init import initialize_database


@click.group('tlssec')
def cli():
    """TLS security monitoring toolkit"""
    logging.basicConfig(
        format = '%(asctime)s %(name)s %(levelname)s: %(message)s',
        level = logging.INFO,
    )
    if get_settings().deployment_mode == 'development':
        logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)


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
def report():
    """Produce report"""
    raise NotImplementedError
