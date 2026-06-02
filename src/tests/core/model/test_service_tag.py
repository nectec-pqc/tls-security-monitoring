from contextlib import nullcontext

import pytest
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlmodel import select

import tlssec.core.model as m


@pytest.mark.parametrize(
    'args, expectation',
    [
        pytest.param(
            {
                'name': 'Valid_Name',
                'description': 'Valid, somewhat long description. สามารถใช้ UTF-8',
            },
            nullcontext(),
            id = 'normal tag construction',
        ),
        pytest.param(
            {'name': ''},
            pytest.raises(ValidationError),
            id = 'tag name can not be empty',
        ),
        pytest.param(
            {'name': 'foo', 'description': ''},
            nullcontext(m.ServiceTag(name = 'foo', description = None)),
            id = 'empty description normalizes to none',
        ),
        pytest.param(
            {'name': '_012345678901234567890123456789'},
            pytest.raises(ValidationError),
            id = 'name too long',
        ),
        pytest.param(
            {'name': 'ใช้ไม่ได้'},
            pytest.raises(ValidationError),
            id = 'name can not use UTF-8',
        ),
    ],
)
def test_tag_validation(args, expectation):
    with expectation as expected:
        result = m.ServiceTag(**args)
        if expected is not None:
            assert result == expected


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
    assert result.children.keys() == {'for-profit', 'non-profit ngo'}


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


def test_error_root_tag_name_not_unique(session):
    tags = [
        m.ServiceTagTable(name = 'root'),
        m.ServiceTagTable(name = 'root'),
    ]

    with pytest.raises(IntegrityError):
        session.add_all(tags)
        session.flush()


def test_error_tag_name_not_unique_among_sibling(session):
    # NOTE: Can't test by adding nested tags because
    # `children` attribute is always converted to dict which forces
    # each child to have different key / name.
    root = m.ServiceTagTable(name = 'root')
    child_a = m.ServiceTagTable(name = 'repeat', parent = root)
    child_b = m.ServiceTagTable(name = 'repeat', parent = root)

    with pytest.raises(IntegrityError):
        session.add_all([root, child_a, child_b])
        session.flush()
