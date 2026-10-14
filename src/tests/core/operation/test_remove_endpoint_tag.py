import pytest

import tlssec.core.operation as op
import tlssec.core.model as m


def test_remove_endpoint_tag(session):
    endpoint = op.make_endpoint(
        session,
        port = 443,
        ip = '10.0.0.1',
        hostname = 'site.net',
        tags = [
            'asia/thailand/bangkok',
            'asia/thailand/nonthaburi',
            'asia/thailand/chengmai',
            'asia/china/beijing',
        ],
    )
    op.remove_endpoint_tag(
        session,
        endpoint,
        'asia/thailand',
    )
    session.flush()
    resulting_tag_paths = {str(tag.fullpath) for tag in endpoint.tags}
    expected_tag_paths = {
        '/asia',
        '/asia/china',
        '/asia/china/beijing',
    }
    assert resulting_tag_paths == expected_tag_paths
