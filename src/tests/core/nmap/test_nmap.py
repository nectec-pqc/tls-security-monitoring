import re
import shutil

import pytest

import tlssec.core.model as m
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
    completed_process, endpoints = await Nmap.discover_endpoints(
        'localhost',
        base_output_dir = cache_dir,
        ports = '4400-4450',
    )
    assert completed_process.returncode == 0
    assert len(endpoints) == 1
    assert endpoints[0].hostname == 'localhost'
    assert endpoints[0].port == 4433
    assert endpoints[0].transport_protocol == 'tcp'
    assert endpoints[0].tls_mode == m.TlsMode.explicit

    # NOTE: The following tests checks XML file directly.

    outfiles = list(clean_nmap_output_dir.glob('*_localhost.nmap.xml'))
    assert len(outfiles) == 1

    from bs4 import BeautifulSoup
    with open(outfiles[0]) as f:
        soup = BeautifulSoup(f, 'xml')

    hosts = soup.find_all('host')
    assert len(hosts) == 1, (
        'Generally, there can be more than one <host> tags.'
        ' A known case is: when user give multiple targets explicitly on command line.'
        ' However, in this test, there we only give one target so there should only be one <host> tag.'
    )
    for host in hosts:
        addresses = host.find_all('address')
        assert len(addresses) == 1, (
            'nmap should be iterating each host based on IP address,'
            ' so there should only be one address per host item.'
            # TODO: try nmap on domain name that maps to multiple IP to confirm this
        )

        ports_tags = host.find_all('ports')
        assert len(ports_tags) == 1, 'There should only be one <ports> tag per host'
        the_ports_tag = ports_tags[0]

        port_tags = the_ports_tag.find_all('port')
        assert len(port_tags) == 51, '--script=ssl-cert should runs on all ports'
        assert all(len(x.find_all('state')) == 1 for x in port_tags), \
            'There shuold only be one state tag inside each port tag'

        open_ports = [x for x in port_tags if x.find('state', state = 'open')]
        assert len(open_ports) == 1, 'There should only be one open port'
        the_open_port = open_ports[0]
        assert the_open_port.attrs['portid'] == '4433'
