import asyncio
import subprocess
from pathlib import Path

import pytest


# TODO: put testssl calling into a reusable function
def test_call_testssl():
    async def call() -> str | None:
        proc = await asyncio.create_subprocess_exec(
            'testssl', '--help',
            stdout = asyncio.subprocess.PIPE,
            stderr = asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(
                proc.communicate(),
                timeout = 1,
            )
            return out.decode()
        except TimeoutError:
            try:
                proc.kill()
            except OSError:
                pass
            await proc.wait()
        return

    result = asyncio.run(call())
    assert 'testssl [options] <URI>' in result



@pytest.fixture(scope = 'module', autouse = True)
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
def test_scan_local():
    async def call():
        proc = await asyncio.create_subprocess_exec(
            'testssl', '--forward-secrecy', 'localhost:4433',
            stdout = asyncio.subprocess.PIPE,
            stderr = asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(
                proc.communicate(),
                timeout = 180,
            )
            return proc.returncode, out.decode(), err.decode()
        except TimeoutError:
            try:
                proc.kill()
            except OSError:
                pass
            out, err = await proc.communicate()
            return proc.returncode, out.decode(), err.decode()

    returncode, out, err = asyncio.run(call())
    assert returncode == 0
