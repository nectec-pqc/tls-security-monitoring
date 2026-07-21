import re
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

import tlssec.core.model as m
from tlssec.asyncio import run_subprocess, CompletedProcess
from tlssec.core.nmap import Nmap


def _port_tag(xml):
    return BeautifulSoup(xml, 'xml').find('port')


def test_detect_tls_mode_tunnel_ssl_is_implicit():
    # nmap -sV positively detected a TLS wrapper.
    port = _port_tag('<port portid="443"><service name="http" tunnel="ssl"/></port>')
    assert Nmap._detect_tls_mode(port) == m.TlsMode.implicit


def test_detect_tls_mode_wrapped_service_name_is_implicit():
    # No -sV: a port-table implicit-TLS service name is enough.
    port = _port_tag('<port portid="465"><service name="smtps"/></port>')
    assert Nmap._detect_tls_mode(port) == m.TlsMode.implicit


def test_detect_tls_mode_ssl_cert_on_implicit_port_is_implicit():
    # No -sV, but a cert on a known wrapped-TLS port -> implicit, not STARTTLS.
    port = _port_tag('<port portid="443"><service name="https"/><script id="ssl-cert"/></port>')
    assert Nmap._detect_tls_mode(port) == m.TlsMode.implicit


def test_detect_tls_mode_ssl_cert_on_starttls_port_is_explicit():
    # A cert obtained on a plaintext port means TLS was negotiated via STARTTLS.
    port = _port_tag('<port portid="25"><service name="smtp"/><script id="ssl-cert"/></port>')
    assert Nmap._detect_tls_mode(port) == m.TlsMode.explicit


def test_detect_tls_mode_no_tls_evidence_is_none():
    port = _port_tag('<port portid="80"><service name="http"/></port>')
    assert Nmap._detect_tls_mode(port) == m.TlsMode.none


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


async def test_discover_endpoints(
    current_openssl_server,
    tmp_path,
):
    # Use a per-test tmp_path as the output base: `discover_endpoints` writes the
    # XML straight into base_output_dir, and pytest cleans tmp_path up for us.
    completed_process, endpoints = await Nmap.discover_endpoints(
        'localhost',
        base_output_dir = tmp_path,
        ports = '4400-4450',
        # Skip -sV to keep the test fast (it is abnormally slow against
        # openssl s_server) and exercise the no-version-detection heuristic.
        detect_version = False,
    )
    assert completed_process.returncode == 0
    assert len(endpoints) == 1
    assert endpoints[0].hostname == 'localhost'
    assert endpoints[0].port == 4433
    assert endpoints[0].transport_protocol == 'tcp'
    # Without -sV there is no tunnel="ssl"; 4433 is a non-standard port with no
    # implicit-TLS service name, so the cert is attributed to STARTTLS. (With
    # -sV this same server is correctly detected as implicit.)
    assert endpoints[0].tls_mode == m.TlsMode.explicit

    # NOTE: The following tests checks XML file directly.

    outfiles = list(tmp_path.glob('nmap/*_localhost.nmap.xml'))
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


@pytest.mark.parametrize(
    'kwargs, filename',
    [
        pytest.param(*x, id = x[1])
        for x in (
            (
                {},
                'success.nmap.xml',
            ),
        )
    ],
)
@pytest.mark.regen_case
async def test_generate_nmap_xml(
    current_openssl_server,
    kwargs,
    filename,
):
    out_dir = Path(__file__).parent / 'result_cases/current_openssl_server'
    out_dir.mkdir(parents = True, exist_ok = True)
    tmp_file = out_dir / 'tmp.xml'
    tmp_file.unlink(missing_ok = True)

    completed_process, endpoints = await Nmap.discover_endpoints(
        'localhost',
        base_output_dir = out_dir,
        xml_path_template = str(tmp_file.relative_to(out_dir)),
        ports = '4400-4450',
        **kwargs,
    )
    assert completed_process.returncode == 0

    with open(out_dir / 'tmp.xml') as f:
        soup = bs4.BeautifulSoup(f, 'xml')
    with open(out_dir / filename, 'w') as f:
        f.write(soup.prettify())

    tmp_file.unlink(missing_ok = True)
