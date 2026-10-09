from contextlib import nullcontext
from dataclasses import dataclass
from typing import Literal

import pytest

import tlssec.core.operation as op
import tlssec.core.model as m


@dataclass
class TestStep:
    requested_tag: str
    create: bool = True
    expected: type[Exception] | Literal['found', 'not-found'] = 'found'


@pytest.mark.parametrize(
    'steps',
    [
        pytest.param(
            [
                TestStep(
                    requested_tag = '',
                    expected = ValueError,
                ),
            ],
            id = 'empty tag name is invalid',
        ),
        pytest.param(
            [TestStep(requested_tag = 'name')],
            id = 'valid single-part tag',
        ),
        pytest.param(
            [TestStep(requested_tag = 'valid/tag/name')],
            id = 'valid multi-part tag',
        ),
        pytest.param(
            [TestStep(requested_tag = '/valid/tag/name')],
            id = 'valid multi-part tag that starts with /',
            marks = pytest.mark.xfail(
                reason = 'TODO: Wants absolute tag path to be supported'
                ' but current implementation cut that out of scope.'
            ),
        ),
        pytest.param(
            [
                TestStep(
                    requested_tag = 'name',
                    create = False,
                    expected = 'not-found',
                ),
            ],
            id = 'tag does not exist yet',
        ),
        pytest.param(
            [
                TestStep(requested_tag = 'root/parent/child'),
                TestStep(
                    requested_tag = 'child',
                    create = False,
                    expected = 'not-found',
                ),
            ],
            id = 'input path is absolute',
        ),
        pytest.param(
            [
                TestStep(requested_tag = 'root/parent/child'),
                TestStep(requested_tag = 'root/parent/child/tag'),
                TestStep(requested_tag = 'root', create = False),
                TestStep(requested_tag = 'root/parent', create = False),
                TestStep(requested_tag = 'root/parent/child'),
            ],
            id = 'repeated overlapping paths',
        ),
    ],
)
def test_resolve_tag(
    session,
    steps,
):
    for step in steps:
        exception_context = (
            pytest.raises(step.expected)
            if isinstance(step.expected, type) else
            nullcontext()
        )
        with exception_context as exception_info:
            result = op.resolve_tag(
                session,
                step.requested_tag,
                create = step.create,
            )
            match step.expected:
                case 'found':
                    assert isinstance(result, m.TagTable)
                    # Ensure returned ORM object actually match what's in database.
                    session.refresh(result)
                    # This assumes we can trust `m.TagTable.fullpath` to actually
                    # reflect the structure of the tag in database. Meaning, this test
                    # depends on the test of `m.TagTable.fullpath` to be passed first.
                    assert str(result.fullpath.relative_to('/')) == step.requested_tag
                case 'not-found':
                    assert result == None


def test_existing_tag_is_returned(session):
    results = {
        'new_single_part': op.resolve_tag(session, 'single_part'),
        'new_multi_part': op.resolve_tag(session, 'multi/part/tag'),
        'already_created_single_part': op.resolve_tag(session, 'single_part'),
        'already_created_multi_part': op.resolve_tag(session, 'multi/part/tag'),
        'already_created_parent': op.resolve_tag(session, 'multi/part'),
    }
    for result in results.values():
        session.refresh(result)
    assert results['new_single_part'] == results['already_created_single_part']
    assert results['new_multi_part'] == results['already_created_multi_part']
    assert results['new_multi_part'].parent == results['already_created_parent']
