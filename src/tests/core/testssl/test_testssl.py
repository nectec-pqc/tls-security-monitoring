import asyncio
import json
from pathlib import Path
import json

import pytest

from tlssec.core.testssl import Testssl
from tlssec.asyncio import CompletedProcess
import tlssec.core.model as m


@pytest.fixture(scope = 'module')
def testssl():
    yield Testssl()
    # TODO: kill all tasks


async def test_call_testssl(testssl):
    result = await testssl.call('--help', timeout = 1)
    assert result.returncode == 0
    assert any('testssl [options] <URI>' in line for line in result.stdout)


async def test_testssl_error(testssl):
    result = await testssl.call(
        '--this-option-is-invalid',
        timeout = 1,
    )
    assert result.returncode != 0


# NOTE: For other kind of scan target,
# we might need to install different version of openssl or nginx into test image.
# Or might even need to use separate container.
# TODO: get output line-by-line, timeout on not getting new line
@pytest.mark.slow
async def test_scan_local(testssl, current_openssl_server):
    result = await testssl.call(
        '--forward-secrecy', 'localhost:4433',
    )
    assert result.returncode == 0
    assert any('X25519MLKEM768' in line for line in result.stdout)


@pytest.mark.parametrize(
    'testssl_opts, call_kwargs, filename',
    [
        pytest.param(*x, id = x[2])
        for x in (
            (
                ('--jsonfile',),
                {},
                'success.json',
            ),
            (
                ('--jsonfile-pretty',),
                {},
                'success.pretty.json',
            ),
            (
                ('--jsonfile',),
                {'idle_timeout': 10},
                'idle_timeout.json',
            ),
            # FIXME: Next process sometimes get stuck after
            # previous process idle_timeout
            (
                ('--jsonfile-pretty',),
                {'idle_timeout': 10},
                'idle_timeout.pretty.json',
            ),
        )
    ],
)
@pytest.mark.regen_case
async def test_generate_testssl_json(
    testssl, current_openssl_server,
    testssl_opts, call_kwargs, filename,
):
    out_dir = Path(__file__).parent / 'result_cases/current_openssl_server'
    out_dir.mkdir(parents = True, exist_ok = True)
    tmp_file = out_dir / 'tmp.json'
    tmp_file.unlink(missing_ok = True)

    result = await testssl.call(
        *testssl_opts, str(tmp_file), 'localhost:4433',
        cwd = out_dir,
        **call_kwargs,
    )

    with open(tmp_file) as f:
        # FIXME: testssl sometimes produce invalid JSON.
        # I have seen --json mode produce the last "scanTime" item
        # outside of its main list.
        content = json.load(f)
    with open(out_dir / filename, 'w') as f:
        json.dump(content, f, indent = 2)
        tmp_file.unlink(missing_ok = True)


# --- Testssl.scan (no real testssl; self.call is faked) --------------------

def _fake_call_writing(result, capture=None):
    """Build a Testssl.call replacement that writes `result` to the jsonfile.

    Mimics testssl: it does not print JSON to stdout, it writes the file named
    by the --jsonfile-pretty argument. Optionally records the args it was given.
    """
    async def fake_call(self, *args, **kwargs):
        if capture is not None:
            capture['args'] = args
        json_path = Path(args[args.index('--jsonfile-pretty') + 1])
        json_path.write_text(json.dumps(result))
        return CompletedProcess(args=args, returncode=0, stdout=[], stderr=[])
    return fake_call


async def test_scan_writes_jsonfile_and_returns_result(monkeypatch):
    ts = Testssl()
    expected = {'scanResult': [{'ip': '127.0.0.1', 'port': '443'}]}
    capture = {}
    monkeypatch.setattr(Testssl, 'call', _fake_call_writing(expected, capture))

    ep = m.Endpoint(ip='127.0.0.1', hostname=None, port=443, tls_mode=m.TlsMode.implicit)
    scan = await ts.scan(ep)

    assert scan.result == expected
    assert scan.start_time is not None
    assert scan.time_taken is not None
    # Implicit TLS: target is host:port, no --starttls.
    assert '127.0.0.1:443' in capture['args']
    assert '--starttls' not in capture['args']


async def test_scan_records_observed_ip_and_sni(monkeypatch):
    ts = Testssl()
    # testssl reports it connected to a different IP than the endpoint's own,
    # as happens behind a load balancer / round-robin DNS.
    result = {'scanResult': [{'ip': '203.0.113.5', 'port': '443'}]}
    monkeypatch.setattr(Testssl, 'call', _fake_call_writing(result))

    ep = m.Endpoint(ip='198.51.100.1', hostname='api.example.com', port=443,
                    tls_mode=m.TlsMode.implicit)
    scan = await ts.scan(ep)

    assert str(scan.observed_ip) == '203.0.113.5'
    assert scan.sni == 'api.example.com'


async def test_scan_strips_scanner_version(monkeypatch):
    ts = Testssl()
    # testssl emits "$VERSION $GIT_REL_SHORT"; a packaged (non-git) install
    # leaves a trailing space, e.g. '3.2.1 '. The structured column is trimmed,
    # while scan.result keeps testssl's output verbatim.
    result = {'version': '3.2.1 ', 'scanResult': [{'ip': '127.0.0.1', 'port': '443'}]}
    monkeypatch.setattr(Testssl, 'call', _fake_call_writing(result))

    ep = m.Endpoint(ip='127.0.0.1', hostname=None, port=443, tls_mode=m.TlsMode.implicit)
    scan = await ts.scan(ep)

    assert scan.scanner_version == '3.2.1'        # trimmed for the structured column
    assert scan.result['version'] == '3.2.1 '     # raw scan kept verbatim


async def test_scan_observed_ip_absent_is_none(monkeypatch):
    ts = Testssl()
    monkeypatch.setattr(Testssl, 'call', _fake_call_writing({'scanResult': []}))

    ep = m.Endpoint(ip='198.51.100.1', hostname=None, port=443,
                    tls_mode=m.TlsMode.implicit)
    scan = await ts.scan(ep)

    assert scan.observed_ip is None
    assert scan.sni is None


async def test_scan_prefers_hostname_over_ip(monkeypatch):
    ts = Testssl()
    capture = {}
    monkeypatch.setattr(Testssl, 'call', _fake_call_writing({}, capture))

    ep = m.Endpoint(ip='127.0.0.1', hostname='example.com', port=8443,
                    tls_mode=m.TlsMode.implicit)
    await ts.scan(ep)
    assert 'example.com:8443' in capture['args']


async def test_scan_explicit_uses_starttls(monkeypatch):
    ts = Testssl()
    capture = {}
    monkeypatch.setattr(Testssl, 'call', _fake_call_writing({}, capture))

    ep = m.Endpoint(ip=None, hostname='mail.example.com', port=25,
                    application_protocol='smtp', tls_mode=m.TlsMode.explicit)
    await ts.scan(ep)

    args = capture['args']
    assert 'mail.example.com:25' in args
    assert args[args.index('--starttls') + 1] == 'smtp'


async def test_scan_explicit_unknown_protocol_raises(monkeypatch):
    ts = Testssl()
    monkeypatch.setattr(Testssl, 'call', _fake_call_writing({}))

    ep = m.Endpoint(ip=None, hostname='host.example.com', port=1234,
                    application_protocol='weirdproto', tls_mode=m.TlsMode.explicit)
    with pytest.raises(ValueError, match='starttls'):
        await ts.scan(ep)


def test_starttls_mapper_values_are_official():
    # Every mapped value must be a protocol testssl.sh --starttls accepts, per
    # the official man page (testssl.sh 3.2, doc/testssl.1.md).
    official = {
        'ftp', 'smtp', 'pop3', 'imap', 'xmpp', 'sieve', 'xmpp-server',
        'telnet', 'ldap', 'irc', 'lmtp', 'nntp', 'postgres', 'mysql',
    }
    assert set(Testssl.STARTTLS_PROTOCOLS.values()) <= official
    # Wrapped / implicit-TLS service names must not be treated as STARTTLS.
    assert not ({'smtps', 'imaps', 'pop3s', 'ftps', 'ldaps'} & set(Testssl.STARTTLS_PROTOCOLS))


async def test_scan_requires_host():
    ts = Testssl()
    ep = m.Endpoint(ip=None, hostname=None, port=443)
    with pytest.raises(ValueError, match='hostname nor ip'):
        await ts.scan(ep)


@pytest.mark.slow
async def test_scan_real_local(testssl, current_openssl_server):
    """End-to-end: really run testssl against the local openssl server."""
    ep = m.Endpoint(ip='127.0.0.1', hostname='localhost', port=4433,
                    tls_mode=m.TlsMode.implicit)
    scan = await testssl.scan(ep)

    assert isinstance(scan.result, dict)
    assert 'scanResult' in scan.result
    assert scan.start_time is not None
    assert scan.time_taken is not None
    # The parsed result is consumable by the existing extractor.
    extracts = Testssl.extract_json(scan.result)
    assert extracts and extracts[0]['port'] == '4433'


async def test_scan_raises_when_testssl_did_not_complete(monkeypatch):
    ts = Testssl()

    async def fake_call(self, *args, **kwargs):
        # Simulate a timeout/kill: run_subprocess returns with .exception set
        # and no output file written.
        return CompletedProcess(
            args=args, returncode=None, stdout=[], stderr=[],
            exception=asyncio.TimeoutError(),
        )

    monkeypatch.setattr(Testssl, 'call', fake_call)

    ep = m.Endpoint(ip='127.0.0.1', hostname=None, port=443, tls_mode=m.TlsMode.implicit)
    with pytest.raises(RuntimeError, match='did not complete'):
        await ts.scan(ep)
