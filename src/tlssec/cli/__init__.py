import click


@click.group('tlssec')
def cli():
    """TLS security monitoring toolkit"""
    pass


@cli.command()
def status():
    """Check system status"""
    raise NotImplementedError
