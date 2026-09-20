import pytest

import tlssec.core.model as m
from tlssec.core.operation import (
    find_new_endpoints,
    endpoint_identity_key,
)


@pytest.mark.parametrize(
    'endpoint, expected',
    [
        pytest.param(
            m.Endpoint(hostname = 'ex.com', ip = '10.0.0.1'),
            ('ex.com', 443, 'tcp'),
            id = 'hostname is preferred over IP',
        ),
        pytest.param(
            m.Endpoint(hostname = None, ip = '10.0.0.1'),
            ('10.0.0.1', 443, 'tcp'),
            id = 'IP-only endpoints still key on the IP',
        ),
    ],
)
def test_endpoint_identity_key(endpoint, expected):
    result = endpoint_identity_key(endpoint)
    assert result == expected


@pytest.mark.parametrize(
    'discovered, existing, expected',
    [
        pytest.param(
            [m.Endpoint(hostname = 'ex.com', ip = '10.0.0.2')],
            [m.Endpoint(hostname = 'ex.com', ip = '10.0.0.1')],
            [],
            id = 'Same hostname with new IP is not considered a new endpoint',
            # For example, when load balancer handed scanner a different backend IP.
        ),
        pytest.param(
            ds := [m.Endpoint(hostname = 'ex.com', ip = '10.0.0.1', port = 8443)],
            [m.Endpoint(hostname = 'ex.com', ip = '10.0.0.1', port = 443)],
            ds,
            id = 'New port on same host is a new endpoint',
        ),
        pytest.param(
            ds := [
                m.Endpoint(hostname = None, ip = '10.0.0.1'),
                m.Endpoint(hostname = None, ip = '10.0.0.9'),
            ],
            [m.Endpoint(hostname = None, ip = '10.0.0.1')],
            [ds[1]],
            id = 'Found one new IP among IP-only entries',
        ),
    ],
)
def test_find_new_endpoints(discovered, existing, expected):
    result = find_new_endpoints(discovered, existing)
    assert result == expected
