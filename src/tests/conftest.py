import subprocess
from pathlib import Path

import pytest
from sqlalchemy.orm import Session
from sqlalchemy import delete

from tlssec.database.database import Database
import tlssec.core.model as model


def pytest_addoption(parser):
    parser.addoption(
        '--regen-case',
        action = 'store_true',
        default = False,
        help = 'Regenerate test cases stored as files instead of running tests.'
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption('--regen-case'):
        skip = pytest.mark.skip(reason = 'disabled during --regen-case')
        for item in items:
            if 'regen_case' not in item.keywords:
                item.add_marker(skip)
    else:
        skip = pytest.mark.skip(reason = 'use --regen-case to run')
        for item in items:
            if 'regen_case' in item.keywords:
                item.add_marker(skip)


@pytest.fixture(scope='session')
def database():
    return Database()


@pytest.fixture(name='session')
def empty_database_session(database):
    connection = database.engine.connect()
    transaction = connection.begin()
    with Session(bind=connection, join_transaction_mode='create_savepoint') as session:
        # Delete children before parents to satisfy FKs:
        # opinion -> cbom -> scan -> endpoint.
        session.execute(delete(model.OpinionTable))
        session.execute(delete(model.CbomTable))
        session.execute(delete(model.ScanTable))
        session.execute(delete(model.EndpointTagMapTable))
        session.execute(delete(model.EndpointTable))
        session.execute(delete(model.TagTable))
        yield session
    transaction.rollback()
    connection.close()


@pytest.fixture(scope='session')
def cache_dir():
    path = Path.home() / '.cache/tlssec/test'
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture(scope = 'module')
def current_openssl_server(cache_dir):
    """Start an openssl server to use as target of test scan on localhost.

    This server will use the current openssl version installed in tlssec image.
    """
    # First ensure server certificate exists. Just issue a self-signed one.
    server_config_dir = cache_dir / 'current_openssl_server'
    server_config_dir.mkdir(parents = True, exist_ok = True)
    subprocess.run(
        [
            'openssl', 'req', '-new', '-x509', '-nodes',
            '-out', 'server.crt',
            '-keyout', 'server.pem',
            '-subj', '/CN=localhost',
        ],
        cwd = server_config_dir,
        check = True,
        timeout = 1,
    )

    # TODO: whole thing needs to handle exception by killing subprocess
    proc = subprocess.Popen(
        [
            'openssl', 's_server',
            '-www',
            '-key', 'server.pem',
            '-cert', 'server.crt',
            '-port', '4433',
        ],
        cwd = server_config_dir,
        stdout = subprocess.PIPE,
        stderr = subprocess.DEVNULL,
    )
    # TODO: add timeout. Need to use asyncio?
    for line in proc.stdout:
        if line == b'ACCEPT\n':
            break
    yield proc
    try:
        proc.terminate()
        proc.wait(timeout = 1)
    except subprocess.TimeoutExpired:
        with proc:
            proc.kill()
