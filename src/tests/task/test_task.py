from dataclasses import dataclass, field

import pytest

from tlssec.task import Task, FirstSuccessTaskGroup, as_task

@pytest.fixture(scope = 'module')
def Append():
    @dataclass(frozen = True, eq = False)
    class _Append(Task):
        item: int

        def step(self, value: str) -> str:
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

    def test_skip_failing_branch(self, Append, Fail):
        root = Append(item = 'a')
        children = [
            Fail(dependency = root),
            Append(item = 'b', dependency = root),
        ]
        group = FirstSuccessTaskGroup(children)
        result = group.run('/')
        assert result == '/ab'

    def test_no_path_to_success(self, Append, Fail):
        root = Append(item = 'a')
        children = [
            Fail(dependency = root),
            Fail(dependency = root),
        ]
        group = FirstSuccessTaskGroup(children)
        with pytest.raises(Exception, match = 'No tasks succeeded'):
            result = group.run('/')

    def test_prefix_shadows_its_child(self, Append):
        root = Append(item = 'a')
        prefix = Append(item = 'b', dependency = root)
        child = Append(item = 'c', dependency = prefix)
        group = FirstSuccessTaskGroup([prefix, child])
        result = group.run('/')
        assert result == '/ab'

    def test_prefix_is_fallback_for_its_child(self, Append, Fail):
        root = Append(item = 'a')
        prefix = Append(item = 'b', dependency = root)
        child = Fail(dependency = prefix)
        group = FirstSuccessTaskGroup([child, prefix])
        result = group.run('/')
        assert result == '/ab'

    def test_unskippable_exception(self, Append, Fail):
        root = Append(item = 'a')
        children = [
            Fail(dependency = root, error = IndexError('Simulated unexpected error that should cause entire task group to fail')),
            Append(item = 'b', dependency = root),
        ]
        group = FirstSuccessTaskGroup(children, skippable = ValueError)
        with pytest.raises(IndexError):
            result = group.run('/')
