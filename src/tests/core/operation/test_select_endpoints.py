import pytest

import tlssec.core.operation as op
import tlssec.core.model as m


@pytest.fixture
def endpoint_zoo(session):
    endpoints = {
        'primary site': op.make_endpoint(
            session,
            port = 443,
            ip = '10.0.0.1',
            hostname = 'site.net',
        ),
        'duplicated site on another port': op.make_endpoint(
            session,
            port = 8443,
            ip = '10.0.0.1',
            hostname = 'site.net',
            tags = ['secondary', 'private'],
        ),
        # NOTE: Duplicated site with only different IP counts as the same endpoint.
        'alternative domain name': op.make_endpoint(
            session,
            port = 443,
            ip = '10.0.0.1',
            hostname = 'alt.site.net',
            tags = ['secondary', 'asia/thailand/bangkok'],
        ),
        'very different ssh server': op.make_endpoint(
            session,
            port = 22,
            ip = '10.0.0.2',
            hostname = None,
            # NOTE: Application_protocol should be set, but make_endpoint does not support that argument.
            # Make_endpoint needs to be refactored.
            tags = ['private', 'vm', 'asia/thailand/pathum_thani'],
        ),
    }
    session.flush()
    return endpoints


@pytest.mark.parametrize(
    'kwargs, expected_keys',
    [
        pytest.param(
            {},
            {
                'primary site',
                'duplicated site on another port',
                'alternative domain name',
                'very different ssh server',
            },
            id = 'No kwargs matches all endpoints',
        ),
        pytest.param(
            {
                'port': 443,
            },
            {
                'primary site',
                'alternative domain name',
            },
            id = 'by port',
        ),
        pytest.param(
            {
                'port': 443,
                'hostnames': ['site.net'],
            },
            {
                'primary site',
            },
            id = 'by port and hostname narrows result',
        ),
        pytest.param(
            {
                'ips': ['11.0.0.1', '10.0.0.1'],
                'hostnames': ['alt.site.net', 'alternative.site.net'],
            },
            {
                'alternative domain name',
            },
            id = 'match any IPs and hostnames provided',
        ),
        pytest.param(
            {
                'tag_paths': ['secondary'],
            },
            {
                'duplicated site on another port',
                'alternative domain name',
            },
            id = 'by tag',
        ),
        pytest.param(
            {
                'tag_paths': ['secondary', 'private'],
            },
            {
                'duplicated site on another port',
            },
            id = 'multiple tags should narrow search',
        ),
        pytest.param(
            {
                'tag_paths': ['asia/thailand/bangkok'],
            },
            {
                'alternative domain name',
            },
            id = 'by leaf-level tag path',
        ),
        pytest.param(
            {
                'tag_paths': ['asia/thailand'],
            },
            {
                'alternative domain name',
                'very different ssh server',
            },
            id = 'by parent-level tag path',
        ),
        pytest.param(
            {
                'tag_paths': ['asia', 'asia/thailand', 'asia/thailand/bangkok'],
            },
            {
                'alternative domain name',
            },
            id = 'explicitly given parent tags has no effect',
        ),
    ],
)
def test_select_endpoints_against_zoo(
    session, endpoint_zoo,
    kwargs, expected_keys,
):
    result = set(op.select_endpoints(session, **kwargs))
    expected = {endpoint_zoo[key] for key in expected_keys}
    assert result == expected
