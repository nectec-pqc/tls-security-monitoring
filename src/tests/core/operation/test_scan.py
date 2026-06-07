import asyncio
import subprocess
from pathlib import Path

import pytest

from tlssec.core.testssl import Testssl


@pytest.fixture(scope = 'module')
def testssl():
    yield Testssl()
    # TODO: kill all tasks


def test_call_testssl(testssl):
    result = asyncio.run(testssl.call('--help', timeout = 1))
    assert result.returncode == 0
    assert 'testssl [options] <URI>' in result.stdout


def test_testssl_error(testssl):
    result = asyncio.run(testssl.call(
        '--this-option-is-invalid',
        timeout = 1,
    ))
    assert result.returncode != 0


@pytest.fixture(scope = 'module')
def current_openssl_server():
    """Start an openssl server to use as target of test scan on localhost.

    This server will use the current openssl version installed in tlssec image.
    """
    # First ensure server certificate exists. Just issue a self-signed one.
    server_config_dir = Path.home() / '.cache/tlssec/test/current_openssl_server'
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


# NOTE: For other kind of scan target,
# we might need to install different version of openssl or nginx into test image.
# Or might even need to use separate container.
# TODO: get output line-by-line, timeout on not getting new line
def test_scan_local(testssl, current_openssl_server):
    result = asyncio.run(testssl.call(
        # TODO: test with faster running option
        '--forward-secrecy', 'localhost:4433',
        timeout = 180,
    ))
    assert result.returncode == 0
    assert 'X25519MLKEM768' in result.stdout
