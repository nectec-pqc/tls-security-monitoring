from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass(frozen = True, kw_only = True)
class Task(ABC):
    dependency: Task | None = None

    def run(self, value):
        if self.dependency is not None:
            value = self.dependency.run(value)
        return self.step(value)

    @abstractmethod
    def step(self, value):
        ...


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
        self.skippable = skippable
        self.children = defaultdict(list)
        # FIXME: task that are prefix of another are getting forgotten.
        # - prefix task that comes before its children should make the children ignorable
        # - prefix task that comes after its children can become fallback for children
        for task in targets:
            self.add_task(task)

    # FIXME: if task hash is deep, then it means we might not need to traverse up?
    def add_task(self, task: Task) -> bool:
        # FIXME: If any ancestor is a target and already registered (has higher priority),
        # the current task can never be reached add we should not register it.

        # NOTE: does not detect cycle
        while task is not None:
            self.children[task.dependency].append(task)
            task = task.dependency
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
            return result
        for child in children:
            try:
                return self.execute_subtree(child, result)
            except self.skippable:
                pass
        # FIXME: If no children were successful, but the current node is a target,
        # use the current result.
        raise Exception('No tasks succeeded')

    def run(self, value):
        return self.execute_subtree(None, value)
