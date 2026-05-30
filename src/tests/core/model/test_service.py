import pytest

import tlssec.core.model as m


def test_traverse_tag_hierarchy(session):
    tags = {}
    def add_tag(**kwargs):
        tag = m.ServiceTagTable(**kwargs)
        tags[tag.name] = tag

    add_tag(
        name = 'organization',
        description = (
            'Service is owned by an organization.'
            ' sub-tag describes organization types.'
        ),
    )
    add_tag(
        name = 'public',
        parent = tags['organization'],
    )
    add_tag(
        name = 'private',
        parent = tags['organization'],
    )
    add_tag(
        name = 'for-profit',
        parent = tags['private'],
    )
    add_tag(
        name = 'non-profit ngo',
        description = 'non-profit non-governmental organization',
        parent = tags['private'],
    )
    add_tag(
        name = 'religious',
        parent = tags['non-profit ngo'],
    )

    add_tag(
        name = 'access-control',
        description = 'tag group describing access control on the service',
    )
    add_tag(
        name = 'no-access-control',
        parent = tags['access-control'],
    )
    add_tag(
        name = 'restricted-access',
        parent = tags['access-control'],
    )

    session.add_all(tags.values())
    results = session.exec(select(m.ServiceTagTable)).all()
    breakpoint()
    # TODO: assert accessing hierarchy

