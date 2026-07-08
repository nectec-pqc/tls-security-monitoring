from datetime import datetime

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


# --- edit endpoint ---------------------------------------------------------
# NOTE: the cli closes/expunges the session on exit, so pre-invoke ORM objects
# become detached. Always re-query by ip after invoke to read the new state.

def _by_ip(session):
    return {str(ep.ip): ep for ep in _endpoints(session)}


def _tag_paths(endpoint):
    return {str(t.fullpath) for t in endpoint.tags}


def test_edit_endpoint_add_tag(runner, session):
    ep = op.make_endpoint(session, 443, '10.0.0.1', None, ['web'])
    session.flush()
    ep_id = ep.id

    result = runner.invoke(
        cli,
        ['edit', 'endpoint', '--id', str(ep_id), '--add-tag', 'network/tls'],
    )
    assert result.exit_code == 0, result.output
    assert _tag_paths(_by_ip(session)['10.0.0.1']) == {'/web', '/network/tls'}


def test_edit_endpoint_remove_tag(runner, session):
    ep = op.make_endpoint(session, 443, '10.0.0.1', None, ['web', 'network/tls'])
    session.flush()
    ep_id = ep.id

    result = runner.invoke(
        cli,
        ['edit', 'endpoint', '--id', str(ep_id), '--remove-tag', 'web'],
    )
    assert result.exit_code == 0, result.output
    assert _tag_paths(_by_ip(session)['10.0.0.1']) == {'/network/tls'}


def test_edit_endpoint_change_tag(runner, session):
    ep = op.make_endpoint(session, 443, '10.0.0.1', None, ['web'])
    session.flush()
    ep_id = ep.id

    result = runner.invoke(
        cli,
        ['edit', 'endpoint', '--id', str(ep_id), '--change-tag', 'web', 'network/tls'],
    )
    assert result.exit_code == 0, result.output
    assert _tag_paths(_by_ip(session)['10.0.0.1']) == {'/network/tls'}


def test_edit_endpoint_disable_by_tag(runner, session):
    # Two endpoints share 'prod'; disabling by tag hits both.
    op.make_endpoint(session, 443, '10.0.0.1', None, ['prod'])
    op.make_endpoint(session, 443, '10.0.0.2', None, ['prod'])
    op.make_endpoint(session, 443, '10.0.0.3', None, ['staging'])
    session.flush()

    result = runner.invoke(cli, ['edit', 'endpoint', '--tag', 'prod', '--disable'])
    assert result.exit_code == 0, result.output

    endpoints = _by_ip(session)
    assert endpoints['10.0.0.1'].retire_at is not None
    assert endpoints['10.0.0.2'].retire_at is not None
    assert endpoints['10.0.0.3'].retire_at is None  # different tag, untouched


def test_edit_endpoint_disable_specific_endpoint(runner, session):
    a = op.make_endpoint(session, 443, '10.0.0.1', None, ['prod'])
    op.make_endpoint(session, 443, '10.0.0.2', None, ['prod'])
    session.flush()
    a_id = a.id

    result = runner.invoke(cli, ['edit', 'endpoint', '--id', str(a_id), '--disable'])
    assert result.exit_code == 0, result.output

    endpoints = _by_ip(session)
    assert endpoints['10.0.0.1'].retire_at is not None
    assert endpoints['10.0.0.2'].retire_at is None  # only the specified endpoint


def test_edit_endpoint_select_by_ip(runner, session):
    op.make_endpoint(session, 443, '10.0.0.1', None, ['prod'])
    op.make_endpoint(session, 443, '10.0.0.2', None, ['prod'])
    session.flush()

    result = runner.invoke(cli, ['edit', 'endpoint', '--ip', '10.0.0.1', '--disable'])
    assert result.exit_code == 0, result.output

    endpoints = _by_ip(session)
    assert endpoints['10.0.0.1'].retire_at is not None
    assert endpoints['10.0.0.2'].retire_at is None


def test_edit_endpoint_select_by_hostname(runner, session):
    op.make_endpoint(session, 443, None, 'a.example.com', ['prod'])
    op.make_endpoint(session, 443, None, 'b.example.com', ['prod'])
    session.flush()

    result = runner.invoke(
        cli, ['edit', 'endpoint', '--hostname', 'a.example.com', '--add-tag', 'network/tls']
    )
    assert result.exit_code == 0, result.output

    by_host = {ep.hostname: ep for ep in _endpoints(session)}
    assert _tag_paths(by_host['a.example.com']) == {'/prod', '/network/tls'}
    assert _tag_paths(by_host['b.example.com']) == {'/prod'}


def test_edit_endpoint_ip_and_port_pin_single_endpoint(runner, session):
    # Same ip, two ports -> --ip + --port pins exactly one.
    op.make_endpoint(session, 443, '10.0.0.1', None, ['prod'])
    op.make_endpoint(session, 8443, '10.0.0.1', None, ['prod'])
    session.flush()

    result = runner.invoke(
        cli, ['edit', 'endpoint', '--ip', '10.0.0.1', '--port', '8443', '--disable']
    )
    assert result.exit_code == 0, result.output

    by_port = {ep.port: ep for ep in _endpoints(session)}
    assert by_port[8443].retire_at is not None
    assert by_port[443].retire_at is None  # other port untouched


def test_edit_endpoint_ip_and_hostname_intersect(runner, session):
    # ip and hostname are ANDed: only the endpoint matching BOTH is selected.
    op.make_endpoint(session, 443, '10.0.0.1', 'a.example.com', ['prod'])
    op.make_endpoint(session, 443, '10.0.0.2', 'b.example.com', ['prod'])
    session.flush()

    result = runner.invoke(
        cli,
        ['edit', 'endpoint', '--ip', '10.0.0.1', '--hostname', 'a.example.com', '--disable'],
    )
    assert result.exit_code == 0, result.output

    endpoints = _by_ip(session)
    assert endpoints['10.0.0.1'].retire_at is not None
    assert endpoints['10.0.0.2'].retire_at is None


def test_edit_endpoint_conflicting_criteria_match_nothing(runner, session):
    # ip of one endpoint + hostname of another -> intersection is empty.
    op.make_endpoint(session, 443, '10.0.0.1', 'a.example.com', ['prod'])
    op.make_endpoint(session, 443, '10.0.0.2', 'b.example.com', ['prod'])
    session.flush()

    result = runner.invoke(
        cli,
        ['edit', 'endpoint', '--ip', '10.0.0.1', '--hostname', 'b.example.com', '--disable'],
    )
    assert result.exit_code == 0, result.output
    assert 'No endpoints matched' in result.output

    endpoints = _by_ip(session)
    assert endpoints['10.0.0.1'].retire_at is None
    assert endpoints['10.0.0.2'].retire_at is None


def test_edit_endpoint_id_and_tag_intersect(runner, session):
    # id 'a' has tag prod; id 'b' has tag staging. --id a --tag staging -> empty.
    a = op.make_endpoint(session, 443, '10.0.0.1', None, ['prod'])
    op.make_endpoint(session, 443, '10.0.0.2', None, ['staging'])
    session.flush()
    a_id = a.id

    result = runner.invoke(
        cli, ['edit', 'endpoint', '--id', str(a_id), '--tag', 'staging', '--disable']
    )
    assert result.exit_code == 0, result.output
    assert 'No endpoints matched' in result.output
    assert _by_ip(session)['10.0.0.1'].retire_at is None


def test_edit_endpoint_repeated_ip_matches_any(runner, session):
    # Two --ip values are ORed within the option.
    op.make_endpoint(session, 443, '10.0.0.1', None, ['prod'])
    op.make_endpoint(session, 443, '10.0.0.2', None, ['prod'])
    op.make_endpoint(session, 443, '10.0.0.3', None, ['prod'])
    session.flush()

    result = runner.invoke(
        cli, ['edit', 'endpoint', '--ip', '10.0.0.1', '--ip', '10.0.0.2', '--disable']
    )
    assert result.exit_code == 0, result.output

    endpoints = _by_ip(session)
    assert endpoints['10.0.0.1'].retire_at is not None
    assert endpoints['10.0.0.2'].retire_at is not None
    assert endpoints['10.0.0.3'].retire_at is None


def test_edit_endpoint_redisable_keeps_original_timestamp(runner, session):
    ep = op.make_endpoint(session, 443, '10.0.0.1', None, ['prod'])
    session.flush()
    ep_id = ep.id

    runner.invoke(cli, ['edit', 'endpoint', '--id', str(ep_id), '--disable'])
    first = _by_ip(session)['10.0.0.1'].retire_at
    assert first is not None

    # Re-disabling (here via a bulk tag select) must not refresh retire_at.
    result = runner.invoke(cli, ['edit', 'endpoint', '--tag', 'prod', '--disable'])
    assert result.exit_code == 0, result.output
    assert _by_ip(session)['10.0.0.1'].retire_at == first


def test_edit_endpoint_change_missing_tag_does_not_add(runner, session):
    ep = op.make_endpoint(session, 443, '10.0.0.1', None, ['web'])
    session.flush()
    ep_id = ep.id

    result = runner.invoke(
        cli,
        ['edit', 'endpoint', '--id', str(ep_id), '--change-tag', 'nope', 'network/tls'],
    )
    assert result.exit_code == 0, result.output
    assert 'no tag "nope"' in result.output
    # network/tls must NOT have been added since 'nope' was not present.
    assert _tag_paths(_by_ip(session)['10.0.0.1']) == {'/web'}


def test_edit_endpoint_select_by_port_only(runner, session):
    op.make_endpoint(session, 443, '10.0.0.1', None, ['prod'])
    op.make_endpoint(session, 443, '10.0.0.2', None, ['prod'])
    op.make_endpoint(session, 8443, '10.0.0.3', None, ['prod'])
    session.flush()

    result = runner.invoke(cli, ['edit', 'endpoint', '--port', '443', '--disable'])
    assert result.exit_code == 0, result.output

    endpoints = _by_ip(session)
    assert endpoints['10.0.0.1'].retire_at is not None
    assert endpoints['10.0.0.2'].retire_at is not None
    assert endpoints['10.0.0.3'].retire_at is None  # different port


def test_edit_endpoint_rejects_invalid_tag(runner, session):
    ep = op.make_endpoint(session, 443, '10.0.0.1', None, ['web'])
    session.flush()
    ep_id = ep.id

    result = runner.invoke(
        cli, ['edit', 'endpoint', '--id', str(ep_id), '--add-tag', 'bad name!']
    )
    assert result.exit_code == 2, result.output
    assert 'invalid tag' in result.output
    # The malformed tag must never be persisted (the whole edit is rolled back).
    names = {t.name for t in session.scalars(select(model.TagTable)).all()}
    assert 'bad name!' not in names


def test_edit_endpoint_enable_reenables_disabled(runner, session):
    ep = op.make_endpoint(session, 443, '10.0.0.1', None, ['prod'])
    ep.retire_at = datetime.now()
    session.flush()

    # Selecting by tag must still find a disabled endpoint to re-enable it.
    result = runner.invoke(cli, ['edit', 'endpoint', '--tag', 'prod', '--enable'])
    assert result.exit_code == 0, result.output
    assert _by_ip(session)['10.0.0.1'].retire_at is None


def test_edit_endpoint_requires_selector(runner, session):
    result = runner.invoke(cli, ['edit', 'endpoint', '--disable'])
    assert result.exit_code == 2, result.output


def test_edit_endpoint_requires_action(runner, session):
    ep = op.make_endpoint(session, 443, '10.0.0.1', None, ['web'])
    session.flush()
    result = runner.invoke(cli, ['edit', 'endpoint', '--id', str(ep.id)])
    assert result.exit_code == 2, result.output


def test_edit_endpoint_unknown_id(runner, session):
    result = runner.invoke(cli, ['edit', 'endpoint', '--id', '999999', '--disable'])
    assert result.exit_code == 2, result.output
    assert 'no endpoint with id' in result.output


def test_edit_endpoint_no_match_is_noop(runner, session):
    result = runner.invoke(cli, ['edit', 'endpoint', '--tag', 'does/not/exist', '--disable'])
    assert result.exit_code == 0, result.output
    assert 'No endpoints matched' in result.output


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


def test_nmap_skips_disabled_endpoint(runner, session, monkeypatch):
    # Only endpoint carrying the tag is disabled -> nothing scannable.
    ep = op.make_endpoint(session, 443, '127.0.0.1', 'localhost', ['network/tls'])
    ep.retire_at = datetime.now()
    session.flush()

    called = False

    async def fake_discover(target, *, ports=None, **kwargs):
        nonlocal called
        called = True
        return None, []

    monkeypatch.setattr(Nmap, 'discover_endpoints', fake_discover)

    result = runner.invoke(cli, ['nmap', '--tag', 'network/tls'])
    assert result.exit_code == 0, result.output
    assert 'No scannable hosts found' in result.output
    assert called is False  # disabled endpoint never triggers a scan


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
