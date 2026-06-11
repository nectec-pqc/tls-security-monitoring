from contextlib import nullcontext

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

import tlssec.core.model as m


# ---------------------------------------------------------------------------
# Pydantic validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    'args, expectation',
    [
        pytest.param(
            {'name': 'valid_service', 'hostname': 'example.com'},
            nullcontext(),
            id='minimal valid service',
        ),
        pytest.param(
            {'name': 'with_Description', 'hostname': 'x.example.com', 'description': 'some text'},
            nullcontext(),
            id='service with description',
        ),
        pytest.param(
            {'name': 'empty_desc', 'hostname': 'x.example.com', 'description': ''},
            nullcontext(m.Service(name='empty_desc', hostname='x.example.com', description=None)),
            id='empty description normalizes to None',
        ),
        pytest.param(
            {'name': '', 'hostname': 'x.example.com'},
            pytest.raises(ValidationError),
            id='name cannot be empty',
        ),
        pytest.param(
            {'name': '123starts_with_digit', 'hostname': 'x.example.com'},
            pytest.raises(ValidationError),
            id='name cannot start with digit',
        ),
        pytest.param(
            {'name': 'has-hyphen', 'hostname': 'x.example.com'},
            pytest.raises(ValidationError),
            id='name cannot contain hyphen',
        ),
        pytest.param(
            {'name': 'a' * 51, 'hostname': 'x.example.com'},
            pytest.raises(ValidationError),
            id='name too long',
        ),
        pytest.param(
            {'name': 'valid', 'hostname': 'x' * 256},
            pytest.raises(ValidationError),
            id='hostname too long',
        ),
        pytest.param(
            {'name': 'no_hostname'},
            pytest.raises(ValidationError),
            id='hostname is required',
        ),
    ],
)
def test_service_validation(args, expectation):
    with expectation as expected:
        result = m.Service(**args)
        if expected is not None:
            assert result == expected


# ---------------------------------------------------------------------------
# ORM / DB integration
# ---------------------------------------------------------------------------

def test_create_and_query_service(session):
    svc = m.ServiceTable(name='my_service', hostname='svc.example.com')
    session.add(svc)
    session.flush()

    result = session.scalars(
        select(m.ServiceTable).where(m.ServiceTable.name == 'my_service')
    ).one()
    assert result.hostname == 'svc.example.com'
    assert result.description is None
    assert result.id is not None


def test_service_name_must_be_unique(session):
    session.add(m.ServiceTable(name='unique_svc', hostname='a.example.com'))
    session.flush()

    with pytest.raises(IntegrityError):
        session.add(m.ServiceTable(name='unique_svc', hostname='b.example.com'))
        session.flush()


def test_service_with_description(session):
    svc = m.ServiceTable(name='described_svc', hostname='x.example.com', description='A description')
    session.add(svc)
    session.flush()

    result = session.scalars(
        select(m.ServiceTable).where(m.ServiceTable.id == svc.id)
    ).one()
    assert result.description == 'A description'


def test_service_tags_relationship(session):
    tag_a = m.ServiceTagTable(name='tag_a')
    tag_b = m.ServiceTagTable(name='tag_b')
    svc = m.ServiceTable(name='tagged_svc', hostname='x.example.com', tags=[tag_a, tag_b])
    session.add(svc)
    session.flush()
    session.refresh(svc)

    assert {t.name for t in svc.tags} == {'tag_a', 'tag_b'}


def test_service_tags_reverse_lookup(session):
    tag = m.ServiceTagTable(name='shared_tag')
    svc1 = m.ServiceTable(name='svc_one', hostname='a.example.com', tags=[tag])
    svc2 = m.ServiceTable(name='svc_two', hostname='b.example.com', tags=[tag])
    session.add_all([svc1, svc2])
    session.flush()
    session.refresh(tag)

    assert {s.name for s in tag.services} == {'svc_one', 'svc_two'}


def test_service_from_attributes(session):
    svc = m.ServiceTable(name='orm_svc', hostname='x.example.com', description='desc')
    session.add(svc)
    session.flush()

    pydantic_svc = m.Service.model_validate(svc)
    assert pydantic_svc.name == 'orm_svc'
    assert pydantic_svc.hostname == 'x.example.com'
    assert pydantic_svc.description == 'desc'
