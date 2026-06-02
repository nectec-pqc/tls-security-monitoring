from pathlib import PurePosixPath

import pytest
from sqlalchemy.exc import CircularDependencyError

import tlssec.core.model as m


def test_fullpath(session):
    tag = m.ServiceTagTable(
        name = 'top',
        children = [
            m.ServiceTagTable(name = 'left'),
            m.ServiceTagTable(
                name = 'right',
                children = [
                    m.ServiceTagTable(name = 'left'),
                    m.ServiceTagTable(name = 'mid'),
                    m.ServiceTagTable(name = 'right'),
                ],
            ),
        ],
    )

    def check_fullpath():
        assert tag.fullpath == PurePosixPath('/top')
        assert tag.children['left'].fullpath == PurePosixPath('/top/left')
        assert tag.children['right'].fullpath == PurePosixPath('/top/right')
        assert tag.children['right'].children['mid'].fullpath == PurePosixPath('/top/right/mid')

    # Use python object ID to detect loop if tag ID has not yet been decided
    check_fullpath()

    session.add(tag)
    session.flush()

    # Even after adding to database, fullpath should work the same
    check_fullpath()


def test_tag_cycle_prevented(session):
    n = 4
    tags = [
        m.ServiceTagTable(name = str(i))
        for i in range(n)
    ]
    for i in range(n):
        tags[i].parent = tags[(i + 1) % n]

    with pytest.raises(ValueError, match = 'tag loop detected'):
        tags[0].fullpath

    # SQLAlchemy ORM detect circular dependency in foreign keys
    # and prevent such record from being created.
    with pytest.raises(CircularDependencyError):
        session.add_all(tags)
        session.flush()


def test_tag_cycle_detected(session):
    # Sneak a circular tags past ORM engine
    # by manually setting the parent_id of the last tag
    # separately from the rest.
    n = 4
    tags = [
        m.ServiceTagTable(name = str(i))
        for i in range(n)
    ]
    for i in range(n - 1):
        tags[i].parent = tags[i + 1]

    session.add_all(tags[:-1])
    session.flush()

    session.refresh(tags[0])
    tags[-1].parent_id = tags[0].id
    session.add(tags[-1])
    session.flush()

    session.refresh(tags[0])
    with pytest.raises(ValueError, match = 'tag loop detected'):
        tags[0].fullpath
