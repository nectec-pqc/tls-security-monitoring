import asyncio
import json

import pytest

from tlssec.core.sshaudit import SshAudit
from tlssec.asyncio import CompletedProcess
import tlssec.core.model as m


def _fake_call(result, *, returncode=3, capture=None):
    """Replace SshAudit.call: ssh-audit writes JSON to stdout (not a file)."""
    async def fake_call(self, *args, **kwargs):
        if capture is not None:
            capture['args'] = args
        return CompletedProcess(
            args=args, returncode=returncode,
            stdout=[json.dumps(result)], stderr=[],
        )
    return fake_call


async def test_scan_parses_json_and_sets_scanner(monkeypatch):
    capture = {}
    expected = {'banner': {'protocol': '2.0'}, 'kex': []}
    monkeypatch.setattr(SshAudit, 'call', _fake_call(expected, capture=capture))

    ep = m.Endpoint(ip='127.0.0.1', hostname=None, port=22,
                    application_protocol='ssh', tls_mode=m.TlsMode.none)
    scan = await SshAudit().scan(ep)

    assert scan.result == expected
    assert scan.scanner == m.Scanner.ssh_audit
    assert scan.scanner_version  # ssh-audit package version
    assert '--json' in capture['args']
    assert '22' in capture['args'] and '127.0.0.1' in capture['args']


async def test_scan_nonzero_returncode_is_not_failure(monkeypatch):
    # ssh-audit exits non-zero (e.g. 3) merely on weak-algorithm warnings.
    monkeypatch.setattr(SshAudit, 'call', _fake_call({'banner': {}}, returncode=3))
    ep = m.Endpoint(ip='127.0.0.1', hostname=None, port=22, tls_mode=m.TlsMode.none)
    scan = await SshAudit().scan(ep)
    assert scan.result == {'banner': {}}


async def test_scan_requires_host():
    ep = m.Endpoint(ip=None, hostname=None, port=22)
    with pytest.raises(ValueError, match='hostname nor ip'):
        await SshAudit().scan(ep)


async def test_scan_unparseable_output_raises(monkeypatch):
    async def fake_call(self, *args, **kwargs):
        return CompletedProcess(args=args, returncode=0, stdout=['not json'], stderr=[])
    monkeypatch.setattr(SshAudit, 'call', fake_call)

    ep = m.Endpoint(ip='127.0.0.1', hostname=None, port=22, tls_mode=m.TlsMode.none)
    with pytest.raises(RuntimeError, match='parseable'):
        await SshAudit().scan(ep)


async def test_scan_terminated_raises(monkeypatch):
    async def fake_call(self, *args, **kwargs):
        return CompletedProcess(
            args=args, returncode=None, stdout=[], stderr=[],
            exception=asyncio.TimeoutError(),
        )
    monkeypatch.setattr(SshAudit, 'call', fake_call)

    ep = m.Endpoint(ip='127.0.0.1', hostname=None, port=22, tls_mode=m.TlsMode.none)
    with pytest.raises(RuntimeError, match='did not complete'):
        await SshAudit().scan(ep)
