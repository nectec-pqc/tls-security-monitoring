import subprocess
from pathlib import Path
from textwrap import dedent

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


@pytest.fixture(scope = 'session')
def tests_root():
    """Parent directory containing all the test files.

    To be used for 'root-relative' referencing of test files.
    """
    return Path(__file__).parent


@pytest.fixture(scope='session')
def cache_dir():
    path = Path.home() / '.cache/tlssec/test'
    path.mkdir(parents=True, exist_ok=True)
    return path


def create_server_cert(
    path: Path,
    key_spec: str,
) -> Path:
    path.mkdir(parents = True, exist_ok = True)
    subprocess.run(
        [
            'openssl', 'req', '-new', '-x509', '-nodes',
            '-out', 'server.crt',
            '-keyout', 'server.pem',
            '-subj', '/CN=localhost',
            '-newkey', key_spec,
        ],
        cwd = path,
        check = True,
        timeout = 1,
    )
    return path


@pytest.fixture(scope = 'session')
def server_cert_rsa2048(cache_dir):
    return create_server_cert(
        cache_dir / 'server_cert/rsa2048',
        'rsa:2048',
    )


@pytest.fixture(scope = 'session')
def server_cert_ed25519(cache_dir):
    return create_server_cert(
        cache_dir / 'server_cert/ed25519',
        'ed25519',
    )


def _current_openssl_server(
    port: int,
    server_cert_dir: Path, 
):
    """Start an openssl server to use as target of test scan on localhost.

    This server will use the current openssl version installed in tlssec image.
    """
    # TODO: whole thing needs to handle exception by killing subprocess
    proc = subprocess.Popen(
        [
            'openssl', 's_server',
            '-www',
            '-key', 'server.pem',
            '-cert', 'server.crt',
            '-port', str(port),
        ],
        cwd = server_cert_dir,
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


@pytest.fixture(scope = 'module')
def current_openssl_server(server_cert_rsa2048):
    yield from _current_openssl_server(
        port = 4433,
        server_cert_dir = server_cert_rsa2048,
    )


def _minihttp(*args):
    proc = subprocess.Popen(
        ['python', '-m', 'tests.fixtures.service.minihttp', *args],
        stdout = subprocess.DEVNULL,
        stderr = subprocess.PIPE,
    )
    for line in proc.stderr:
        if b'Uvicorn running on' in line:
            break
    yield proc
    try:
        proc.terminate()
        proc.wait(timeout = 1)
    except subprocess.TimeoutExpired:
        with proc:
            proc.kill()


@pytest.fixture(scope = 'module')
def minihttp_port5500_no_tls():
    yield from _minihttp('--port', '5500')


@pytest.fixture(scope = 'module')
def minihttp_port5501_1cert(
    server_cert_ed25519,
):
    yield from _minihttp(
        '--port', '5501',
        '--cert', str(server_cert_ed25519),
    )


@pytest.fixture(scope = 'module')
def minihttp_port5502_2certs(
    server_cert_ed25519,
    server_cert_rsa2048,
):
    yield from _minihttp(
        '--port', '5502',
        '--cert', str(server_cert_ed25519),
        '--cert', str(server_cert_rsa2048),
    )


@pytest.fixture(scope = 'module')
def current_openssh_server(cache_dir):
    server_config_dir = (cache_dir / 'current_openssh_server').resolve()
    server_config_dir.mkdir(parents = True, exist_ok = True)

    private_key_path = server_config_dir / 'ssh_host_ed25519_key'
    private_key_path.unlink(missing_ok = True)

    public_key_path = private_key_path.with_suffix('.pub')
    public_key_path.unlink(missing_ok = True)

    subprocess.run(
        [
            'ssh-keygen',
            '-t', 'ed25519',
            '-f', 'ssh_host_ed25519_key',
            '-N', '',
        ],
        cwd = server_config_dir,
        check = True,
        timeout = 1,
    )

    sshd_config_path = server_config_dir / 'sshd_config'
    sshd_config_path.unlink(missing_ok = True)

    with open(sshd_config_path, 'w') as f:
        f.write(dedent(f"""
            Port 2222
            ListenAddress 127.0.0.1
            PidFile {server_config_dir / 'sshd.pid'}
            HostKey {server_config_dir / 'ssh_host_ed25519_key'}
            PasswordAuthentication yes
            PermitRootLogin no
        """))

    proc = subprocess.Popen(
        [
            '/usr/sbin/sshd', '-D', '-e',
            '-f', str(sshd_config_path),
        ],
        cwd = server_config_dir,
        stdout = subprocess.DEVNULL,
        stderr = subprocess.PIPE,
    )
    for line in proc.stderr:
        if line.startswith(b'Server listening on'):
            break
    yield proc
    try:
        proc.terminate()
        proc.wait(timeout = 1)
    except subprocess.TimeoutExpired:
        with proc:
            proc.kill()
