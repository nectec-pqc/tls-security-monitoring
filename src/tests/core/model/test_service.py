import pytest
from sqlmodel import select

import tlssec.core.model as m


def test_traverse_tag_hierarchy(session):
    tags = {}
    def add_tag(**kwargs):
        tag = m.ServiceTagTable(**kwargs)
        tags[tag.name] = tag

    # Add a hierarchy of tags with `organization` as root
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

    # Add another hierarchy of tags with `access-control` as root
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
    
    # Readback and check tag hierarchy can be accessed through relationship attributes
    result = session.exec(
        select(m.ServiceTagTable)
            .where(m.ServiceTagTable.name == 'private')
    ).all()
    assert len(result) == 1
    result = result[0]
    assert result.parent.name == 'organization'
    assert {child.name for child in result.children} == {'for-profit', 'non-profit ngo'}
    # TODO: Make `children` attribute a dict for easier access
    # TODO: enforce uniqueness of children name belonging to the same parent
    # See https://docs.sqlalchemy.org/en/21/orm/collection_api.html#dictionary-collections
