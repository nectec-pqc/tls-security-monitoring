import pytest
from click.testing import CliRunner
from sqlalchemy import select

from tlssec.cli import cli, Nmap
from tlssec.database.database import Database
import tlssec.core.model as model
import tlssec.core.operation as op


@pytest.fixture(name='runner')
def cli_runner(session, monkeypatch):
    """
        This fix two problem
        1. inject session into cli, let us have easy way to access to session since our cli alwyas create they own session
        2. from using session fixture we get the rollback affect. Clean product DB
    """
    monkeypatch.setattr(Database, 'session', property(lambda self: session))
    return CliRunner()


def _endpoints(session):
    return list(session.scalars(select(model.EndpointTable)).all())


def test_cli_home():
    runner = CliRunner()
    result = runner.invoke(cli)
    assert result.exit_code == 2, 'Expect "usage error" due to no subcommand selected'


def test_add_endpoint_by_ip_with_tag(runner, session):
    result = runner.invoke(
        cli,
        ['add', 'endpoint', '--ip', '10.0.0.1', '--port', '8443', '--tag', 'network/tls'],
    )
    assert result.exit_code == 0, result.output

    endpoints = _endpoints(session)
    assert len(endpoints) == 1
    ep = endpoints[0]
    assert str(ep.ip) == '10.0.0.1'
    assert ep.port == 8443
    assert {str(t.fullpath) for t in ep.tags} == {'/network/tls'}


def test_add_endpoint_by_hostname(runner, session):
    result = runner.invoke(
        cli,
        ['add', 'endpoint', '--hostname', 'example.com', '--tag', 'web'],
    )
    assert result.exit_code == 0, result.output

    endpoints = _endpoints(session)
    assert len(endpoints) == 1
    assert endpoints[0].hostname == 'example.com'
    assert endpoints[0].port == 443  # default
    assert {t.name for t in endpoints[0].tags} == {'web'}


def test_add_endpoint_requires_target(runner, session):
    result = runner.invoke(cli, ['add', 'endpoint', '--tag', 'web'])
    assert result.exit_code == 2, result.output
    assert _endpoints(session) == []


def test_add_endpoint_rejects_file_and_target(runner, session, tmp_path):
    from_file = tmp_path / 'endpoints.yaml'
    from_file.write_text('- hostname: example.com\n')
    result = runner.invoke(
        cli,
        ['add', 'endpoint', '--from_file', str(from_file), '--ip', '10.0.0.1'],
    )
    assert result.exit_code == 2, result.output
    assert _endpoints(session) == []


def test_add_endpoint_from_file(runner, session, tmp_path):
    from_file = tmp_path / 'endpoints.yaml'
    from_file.write_text(
        '- hostname: a.example.com\n'
        '  port: 443\n'
        '  tags: [imported]\n'
        '- hostname: b.example.com\n'
        '  port: 8443\n'
    )
    # `--tag` applies to every endpoint in the file, `tags:` is per-endpoint.
    result = runner.invoke(
        cli,
        ['add', 'endpoint', '--from_file', str(from_file), '--tag', 'batch'],
    )
    assert result.exit_code == 0, result.output

    endpoints = {ep.hostname: ep for ep in _endpoints(session)}
    assert set(endpoints) == {'a.example.com', 'b.example.com'}
    assert {t.name for t in endpoints['a.example.com'].tags} == {'batch', 'imported'}
    assert {t.name for t in endpoints['b.example.com'].tags} == {'batch'}


# --- nmap ------------------------------------------------------------------

def test_nmap_no_matching_endpoints(runner, session):
    result = runner.invoke(cli, ['nmap', '--tag', 'does/not/exist'])
    assert result.exit_code == 0, result.output
    assert 'No endpoints found' in result.output


def test_nmap_discovers_and_adds_endpoint(runner, session, monkeypatch):
    # Seed an existing endpoint so the tag resolves and gives nmap a host.
    op.make_endpoint(session, 443, '127.0.0.1', 'localhost', ['network/tls'])
    session.flush()

    discovered = [
        model.Endpoint(
            ip='127.0.0.1',
            hostname='localhost',
            port=8443,
            application_protocol='https',
            tls_mode=model.TlsMode.implicit,
        )
    ]

    async def fake_discover(target, *, ports=None, **kwargs):
        return None, discovered

    monkeypatch.setattr(Nmap, 'discover_endpoints', fake_discover)

    result = runner.invoke(cli, ['nmap', '--tag', 'network/tls'], input='y\n')
    assert result.exit_code == 0, result.output
    assert 'Found 1 new endpoint' in result.output

    ports = {ep.port for ep in _endpoints(session)}
    assert ports == {443, 8443}

    new_ep = next(ep for ep in _endpoints(session) if ep.port == 8443)
    assert {str(t.fullpath) for t in new_ep.tags} == {'/network/tls'}


def test_nmap_declined_endpoint_not_added(runner, session, monkeypatch):
    op.make_endpoint(session, 443, '127.0.0.1', 'localhost', ['network/tls'])
    session.flush()

    discovered = [
        model.Endpoint(
            ip='127.0.0.1',
            hostname='localhost',
            port=8443,
            application_protocol='https',
            tls_mode=model.TlsMode.implicit,
        )
    ]

    async def fake_discover(target, *, ports=None, **kwargs):
        return None, discovered

    monkeypatch.setattr(Nmap, 'discover_endpoints', fake_discover)

    result = runner.invoke(cli, ['nmap', '--tag', 'network/tls'], input='n\n')
    assert result.exit_code == 0, result.output

    ports = {ep.port for ep in _endpoints(session)}
    assert ports == {443}  # declined 8443 was not persisted


def test_nmap_no_new_endpoints(runner, session, monkeypatch):
    op.make_endpoint(session, 443, '127.0.0.1', 'localhost', ['network/tls'])
    session.flush()

    # nmap re-discovers the same endpoint that already exists -> nothing new.
    discovered = [
        model.Endpoint(
            ip='127.0.0.1',
            hostname='localhost',
            port=443,
            application_protocol='https',
            tls_mode=model.TlsMode.implicit,
        )
    ]

    async def fake_discover(target, *, ports=None, **kwargs):
        return None, discovered

    monkeypatch.setattr(Nmap, 'discover_endpoints', fake_discover)

    result = runner.invoke(cli, ['nmap', '--tag', 'network/tls'])
    assert result.exit_code == 0, result.output
    assert 'No new endpoints discovered' in result.output
    assert {ep.port for ep in _endpoints(session)} == {443}
