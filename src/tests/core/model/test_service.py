import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import select

import tlssec.core.model as m


def test_traverse_tag_hierarchy(session):
    tags = [
        m.ServiceTagTable(
            name = 'organization',
            description = (
                'Service is owned by an organization.'
                ' sub-tag describes organization types.'
            ),
            children = [
                m.ServiceTagTable(name = 'public'),
                m.ServiceTagTable(
                    name = 'private',
                    children = [
                        m.ServiceTagTable(name = 'for-profit'),
                        m.ServiceTagTable(
                            name = 'non-profit ngo',
                            description = 'non-profit non-governmental organization',
                            children = [m.ServiceTagTable(name = 'religious')],
                        ),
                    ],
                ),
            ],
        ),
        m.ServiceTagTable(
            name = 'access-control',
            description = 'tag group describing access control on the service',
            children = [
                m.ServiceTagTable(name = 'no-access-control'),
                m.ServiceTagTable(name = 'restricted-access'),
            ],
        ),
    ]
    session.add_all(tags)
    
    # Readback and check tag hierarchy can be accessed through relationship attributes
    results = session.exec(
        select(m.ServiceTagTable)
            .where(m.ServiceTagTable.name == 'private')
    ).all()
    assert len(results) == 1
    result = results[0]
    assert result.parent.name == 'organization'
    assert {child.name for child in result.children} == {'for-profit', 'non-profit ngo'}
    # TODO: Make `children` attribute a dict for easier access
    # See https://docs.sqlalchemy.org/en/21/orm/collection_api.html#dictionary-collections


def test_tag_name_can_repeat_if_parents_differ(session):
    tags = [
        m.ServiceTagTable(
            name = 'root-1',
            children = [
                m.ServiceTagTable(
                    name = 'parent-under-root-1',
                    children = [m.ServiceTagTable(name = 'repeat')],
                ),
                m.ServiceTagTable(name = 'repeat'),
            ],
        ),
        m.ServiceTagTable(
            name = 'root-2',
            children = [m.ServiceTagTable(name = 'repeat')],
        ),
    ]
    session.add_all(tags)

    results = session.exec(
        select(m.ServiceTagTable)
            .where(m.ServiceTagTable.name == 'repeat')
    ).all()
    assert len(results) == 3
    assert {result.parent.name for result in results} == {
        'root-1',
        'root-2',
        'parent-under-root-1',
    }


def test_error_tag_name_not_unique_among_sibling(session):
    tag = m.ServiceTagTable(
        name = 'root',
        children = [
            m.ServiceTagTable(name = 'repeat'),
            m.ServiceTagTable(name = 'repeat'),
        ],
    )

    with pytest.raises(IntegrityError):
        session.add(tag)
        session.flush()
