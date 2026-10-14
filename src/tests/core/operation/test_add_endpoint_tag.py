import pytest

import tlssec.core.operation as op
import tlssec.core.model as m


def test_add_endpoint_tag(session):
    endpoint = op.make_endpoint(
        session,
        port = 443,
        ip = '10.0.0.1',
        hostname = 'site.net',
    )
    for name in ('api', 'asia/thailand/bangkok'):
        op.add_endpoint_tag(
            session,
            endpoint,
            name,
        )
    session.flush()
    resulting_tag_paths = {str(tag.fullpath) for tag in endpoint.tags}
    expected_tag_paths = {
        '/api',
        '/asia',
        '/asia/thailand',
        '/asia/thailand/bangkok',
    }
    assert resulting_tag_paths == expected_tag_paths
