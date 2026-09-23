import pytest

from tlssec.timer import Timer


def test_initial_state():
    timer = Timer()

    assert timer.elapsed is None
    assert timer.start_time is None


def test_start():
    timer = Timer()

    timer.start()

    assert timer.start_time is not None
    assert timer.elapsed is None


def test_stop():
    timer = Timer()

    timer.start()
    timer.stop()

    assert timer.start_time is not None
    assert 0 <= timer.elapsed <= 1


def test_stop_without_start():
    timer = Timer()

    with pytest.raises(RuntimeError, match="Timer has not been started"):
        timer.stop()


def test_start_resets_elapsed():
    timer = Timer()

    timer.start()
    timer.stop()
    assert timer.start_time is not None
    assert 0 <= timer.elapsed <= 1

    timer.start()

    assert timer.elapsed is None
    assert timer.start_time is not None


def test_context_manager():
    with Timer() as timer:
        assert timer.elapsed is None
        assert timer.start_time is not None

    assert 0 <= timer.elapsed <= 1


def test_context_manager_stops_on_exception():
    timer = Timer()

    with pytest.raises(ValueError):
        with timer:
            raise ValueError("something went wrong")

    assert 0 <= timer.elapsed <= 1
