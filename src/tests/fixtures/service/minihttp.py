from pathlib import Path
import ssl

import click
from fastapi import FastAPI
import uvicorn


app = FastAPI()


@app.get('/')
def read_root():
    return {'status': 'ready'}


def ssl_context_factory(
    server_cert_dirs: list[Path],
) -> ssl.SSLContext:
    """Create SSL context based on settings specific to this CLI."""
    if not server_cert_dirs:
        raise ValueError('server_cert_dirs can not be empty')

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    for base in server_cert_dirs:
        context.load_cert_chain(
            base / 'server.crt',
            base / 'server.pem',
        )

    return context


@click.command('minihttp')
@click.option(
    '--port',
    type = int,
    required = True,
)
@click.option(
    '--cert', 'server_cert_dirs',
    type = click.Path(
        exists = True,
        file_okay = False,
        path_type = Path,
    ),
    multiple = True,
    help = 'Path to directory containing `server.crt` and `server.pem` to use as server certificate and private key.',
)
def cli(port, server_cert_dirs):
    """Minimal HTTP server with configurable TLS settings

    to be used as scanning test target.
    """
    extra_args = {}
    if server_cert_dirs:
        extra_args['ssl_context_factory'] = (
            # Uvicorn pass these args for to custom SSL context factory so it can extend uvicorn's default behaviour.
            # However, we are going to replace the factory entirely and construct based only on our CLI's options.
            lambda config, default_factory:
            ssl_context_factory(server_cert_dirs)
        )

    uvicorn.run(
        'tests.fixtures.service.minihttp:app',
        host = '127.0.0.1',
        port = port,
        **extra_args,
    )


if __name__ == '__main__':
    cli()
