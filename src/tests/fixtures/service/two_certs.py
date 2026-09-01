from collections.abc import Callable
from pathlib import Path
import ssl

from fastapi import FastAPI
import uvicorn


app = FastAPI()


@app.get('/')
def read_root():
    return {'status': 'ready'}


def ssl_context_factory(
    # NOTE: Both of these arguments are provided by uvicorn for use in
    # constructing SSL context based on configuration that uvicorn receive and
    # existing SSL factory method. However, we are ignoring both of them to
    # construct our own SSL context from scratch.
    config: Config,
    default_factory: Callable[[], ssl.SSLContext],
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    # TODO: parameterize
    base = Path('/home/tlssec/.cache/tlssec/test/server_cert')
    context.load_cert_chain(
        base / 'rsa2048/server.crt',
        base / 'rsa2048/server.pem',
    )
    context.load_cert_chain(
        base / 'ed25519/server.crt',
        base / 'ed25519/server.pem',
    )

    return context


if __name__ == '__main__':
    uvicorn.run(
        'tests.fixtures.service.two_certs:app',
        host = '127.0.0.1',
        port = 5502,
        ssl_context_factory = ssl_context_factory,
    )
