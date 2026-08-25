from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Callable, Any


@dataclass(frozen = True, kw_only = True, eq = False)
class Task(ABC):
    dependency: Task | None = None

    def run(self, value):
        if self.dependency is not None:
            value = self.dependency.run(value)
        return self.step(value)

    # NOTE: Can improve by defining `Task[Tin, TOut]` as generic type.
    # However, this be quite complicated. Leave it for now.
    @abstractmethod
    def step(self, value):
        ...

    def walk(self) -> Iterator[Task]:
        # NOTE: Does not detect cycle.
        # The task chain is cycle-free if dependency is immutable.
        task = self
        while True:
            yield task
            task = task.dependency
            if task is None:
                break


@dataclass(frozen = True, kw_only = True, eq = False)
class TaskFromFunc(Task):
    step_func: Callable[[Any], Any]

    def step(self, value):
        return self.step_func(value)


def as_task(dependency: Task | None = None):
    def decorator(f: Callable[[Any], Any]):
        return TaskFromFunc(dependency = dependency, step_func = f)
    return decorator


class FirstSuccessTaskGroup:
    """Group of subtasks to try one-by-one and return with first successful result.

    Caching:

    - Common dependencies are never re-run.
    - Result of all steps are assumed to be cachable.

    Ordering:

    - Tasks are (mainly) tried in the order they are given on group creation.
    - Except, tasks sharing the same dependency will be exhaustively tried first
      before moving on to the next task in the given order.
    - This can be visualized as doing depth-first search (DFS) from the root
      of dependency tree for the first task that will be successful.
    - DFS order allow cached result to be  is a deliberate choice to minimize memory footprint used for
      caching intermediate results.
    """
    def __init__(
        self,
        targets: list[Task],
        skippable: type[Exception] = Exception,
    ):
        """Create FirstSuccessTaskGroup

        Arguments
        ---------
        targets:
            List of target tasks to try to complete.
        skippable:
            Type of exception that is considered skippable.
            Task raising this exception will be skipped and the next task will be tried next.
            Task raising other kind of exception will terminate the whole runner.
        """
        self.targets = []
        self.skippable = skippable
        self.children = defaultdict(list)
        # FIXME: task that are prefix of another are getting forgotten.
        # - prefix task that comes before its children should make the children ignorable
        # - prefix task that comes after its children can become fallback for children
        for task in targets:
            self.add_task(task)

    # FIXME: if task hash is deep, then it means we might not need to traverse up?
    def add_task(self, task: Task) -> bool:
        # If any ancestor is already a target (which it must have higher priority than new task too),
        # then just don't register the new task (because the new task would be unreachable anyway).
        #
        # This also exclude duplicated task.
        for step in task.walk():
            if step in self.targets:
                return False

        for step in task.walk():
            self.children[step.dependency].append(step)
        self.targets.append(task)
        return True

    def execute_subtree(self, root: Task, value):
        # TODO: Only cache result at node with multiple children in dependency tree.
        result = (
            value
            if root is None
            else root.step(value)
        )
        children = self.children[root]
        if not children:
            # assert root in self.targets, 'All terminal task must be in target set due to initialization logic.'
            return result
        for child in children:
            try:
                return self.execute_subtree(child, result)
            except self.skippable:
                pass
        if root in self.targets:
            return result
        raise Exception('No tasks succeeded')

    def run(self, value):
        return self.execute_subtree(None, value)
