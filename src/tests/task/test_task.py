from dataclasses import dataclass, field

import pytest

from tlssec.task import Task, FirstSuccessTaskGroup

@pytest.fixture(scope = 'module')
def Append():
    @dataclass(frozen = True)
    class _Append(Task):
        item: int

        def step(self, value: str) -> str:
            return value + self.item
    return _Append


@pytest.fixture(scope = 'module')
def Fail():
    class _Fail(Task):
        def step(self, value):
            raise Exception
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


def test_task_deep_equality(Append):
    tasks = []
    a1 = Append(item = 'a')
    a2 = Append(item = 'a')
    b1 = Append(item = 'b', dependency = a1)
    b2 = Append(item = 'b', dependency = a2)
    assert a1 == a2
    assert b1 == b2


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
