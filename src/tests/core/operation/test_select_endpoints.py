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
            tags = ['secondary'],
        ),
        # NOTE: Duplicated site with only different IP counts as the same endpoint.
        'alternative domain name': op.make_endpoint(
            session,
            port = 443,
            ip = '10.0.0.1',
            hostname = 'alt.site.net',
            tags = ['secondary'],
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
            },
            id = 'No kwargs matches all endpoints',
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
