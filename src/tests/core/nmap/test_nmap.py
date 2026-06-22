import re
import shutil

import pytest

from tlssec.asyncio import run_subprocess, CompletedProcess
from tlssec.core.nmap import Nmap


async def test_call_nmap():
    result = await run_subprocess(
        'nmap', '--help',
    )
    assert result.returncode == 0
    assert any('Usage: nmap' in line for line in result.stdout)


# TODO: Test XML export `-oX output.xml`
# TODO: Need extra privilege to use TCP SYN detection
# NOTE: `nmap -sV` takes abnormally long time against `openssl s_server`
async def test_scan_local_found(current_openssl_server):
    result = await run_subprocess(
        'nmap',
        '--script=ssl-cert',
        # Scope to specific port range to make the test quicker
        '-p4400-4450',
        'localhost',
    )
    assert result.returncode == 0
    for pattern in (
        # Must find the open port
        re.compile(r'4433/tcp\s*open'),
        # Must find server certificate
        re.compile(r'subject.*localhost', re.IGNORECASE),
    ):
        assert any(pattern.search(line) for line in result.stdout)


async def test_scan_local_not_found(current_openssl_server):
    result = await run_subprocess(
        'nmap',
        '--script=ssl-cert',
        '-p4450-4500',
        'localhost',
    )
    assert result.returncode == 0
    assert any('51 closed' in line for line in result.stdout), \
        'Must see all ports as closed'


@pytest.fixture
def clean_nmap_output_dir(cache_dir):
    output_dir = cache_dir / 'nmap'

    def clear():
        if output_dir.exists():
            if output_dir.is_dir():
                shutil.rmtree(output_dir)
            else:
                output_dir.unlink()

    clear()
    yield output_dir
    clear()


async def test_discover_endpoints(
    current_openssl_server,
    cache_dir,
    clean_nmap_output_dir,
):
    result = await Nmap.discover_endpoints(
        'localhost',
        base_output_dir = cache_dir,
        detect_version = False,
        ports = '4400-4450',
    )
    outfiles = list(clean_nmap_output_dir.glob('*_localhost.nmap.xml'))
    assert len(outfiles) == 1
    # TODO: test content
