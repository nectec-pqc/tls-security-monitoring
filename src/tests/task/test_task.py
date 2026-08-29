from dataclasses import dataclass, field

import pytest

from tlssec.task import (
    AllAlternativesFailledError,
    FirstSuccessTaskGroup,
    Task,
    as_task,
)

@pytest.fixture(scope = 'module')
def Append():
    @dataclass(frozen = True, eq = False)
    class _Append(Task):
        item: int
        # Tracks number of times `step()` method is called for performance assertion.
        step_count: int = 0

        def step(self, value: str) -> str:
            # bypass frozen
            object.__setattr__(self, 'step_count', self.step_count + 1)
            return value + self.item
    return _Append


@pytest.fixture(scope = 'module')
def Fail():
    @dataclass(frozen = True, eq = False)
    class _Fail(Task):
        error: Exception = Exception()
        def step(self, value):
            raise self.error
    return _Fail


def test_task_chain(Append):
    tasks = []
    tasks.append(Append(item = 'a'))
    tasks.append(Append(item = 'b', dependency = tasks[-1]))
    tasks.append(Append(item = 'c', dependency = tasks[-1]))

    result = tasks[-1].run('/')
    assert result == '/abc'
    for task in tasks:
        assert task.step_count == 1


def test_task_walk(Append):
    tasks = []
    tasks.append(Append(item = 'a'))
    tasks.append(Append(item = 'b', dependency = tasks[-1]))
    tasks.append(Append(item = 'c', dependency = tasks[-1]))

    result = list(tasks[-1].walk())
    expected = list(reversed(tasks))
    assert result == expected


class TestAsTaskDecorator:
    def test_no_dependency(self):
        @as_task()
        def append_a(value: str) -> str:
            return value + 'a'

        result = append_a.run('/')
        assert result == '/a'

    def test_with_dependency(self):
        @as_task()
        def append_a(value: str) -> str:
            return value + 'a'

        @as_task(dependency = append_a)
        def append_ab(value: str) -> str:
            return value + 'b'

        result = append_ab.run('/')
        assert result == '/ab'


class TestFirstSuccessTaskGroup:
    def test_prefer_given_order(self, Append, Fail):
        root = Append(item = 'a')
        children = [
            Append(item = 'b', dependency = root),
            Append(item = 'B', dependency = root),
        ]
        group = FirstSuccessTaskGroup(children)
        result = group.run('/')
        assert result == '/ab'
        assert root.step_count == 1, 'common root should only be executed once'
        assert children[0].step_count == 1
        assert children[1].step_count == 0, 'second child should not be reached since first child already succeeded'

    def test_skip_failing_branch(self, Append, Fail):
        root = Append(item = 'a')
        children = [
            Fail(dependency = root),
            Append(item = 'b', dependency = root),
        ]
        group = FirstSuccessTaskGroup(children)
        result = group.run('/')
        assert result == '/ab'
        assert root.step_count == 1
        assert children[1].step_count == 1

    def test_no_path_to_success(self, Append, Fail):
        root = Append(item = 'a')
        children = [
            Fail(dependency = root),
            Fail(dependency = root),
        ]
        group = FirstSuccessTaskGroup(children)
        with pytest.raises(AllAlternativesFailledError):
            result = group.run('/')
        assert root.step_count == 1

    def test_prefix_shadows_its_child(self, Append):
        root = Append(item = 'a')
        prefix = Append(item = 'b', dependency = root)
        child = Append(item = 'c', dependency = prefix)
        group = FirstSuccessTaskGroup([prefix, child])
        result = group.run('/')
        assert result == '/ab'
        assert root.step_count == 1
        assert prefix.step_count == 1
        assert child.step_count == 0

    def test_prefix_is_fallback_for_its_child(self, Append, Fail):
        root = Append(item = 'a')
        prefix = Append(item = 'b', dependency = root)
        child = Fail(dependency = prefix)
        group = FirstSuccessTaskGroup([child, prefix])
        result = group.run('/')
        assert result == '/ab'
        assert root.step_count == 1
        assert prefix.step_count == 1

    def test_unskippable_exception(self, Append, Fail):
        root = Append(item = 'a')
        children = [
            Fail(dependency = root, error = IndexError('Simulated unexpected error that should cause entire task group to fail')),
            Append(item = 'b', dependency = root),
        ]
        group = FirstSuccessTaskGroup(children, skippable = ValueError)
        with pytest.raises(IndexError):
            result = group.run('/')
        assert root.step_count == 1
        assert children[1].step_count == 0
