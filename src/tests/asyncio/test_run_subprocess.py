import pytest
from pathlib import Path

from tlssec.asyncio import run_subprocess


async def test_success_with_stdout():
    cwd = Path(__file__).parent
    result = await run_subprocess(
        'pwd',
        cwd = cwd,
    )
    assert result.returncode == 0
    assert result.stdout == [f'{cwd}\n']
    assert result.stderr == []
    assert result.exception is None


async def test_success_with_stderr():
    result = await run_subprocess(
        'bash', '-c', 'echo info 1>&2',
    )
    assert result.returncode == 0
    assert result.stdout == []
    assert result.stderr == ['info\n']
    assert result.exception is None


async def test_false():
    result = await run_subprocess('false')
    assert isinstance(result.returncode, int)
    assert result.returncode != 0
    assert result.stdout == []
    assert result.stderr == []
    assert result.exception is None


async def test_failure_to_create_subprocess():
    with pytest.raises(FileNotFoundError):
        result = await run_subprocess('not-a-real-command')


@pytest.mark.slow
async def test_timeout_error():
    result = await run_subprocess(
        'sleep', '1',
        timeout = .5,
    )
    assert result.returncode is None
    assert result.stdout == []
    assert result.stderr == []
    assert isinstance(result.exception, TimeoutError)


@pytest.mark.slow
async def test_timeout_ok():
    result = await run_subprocess(
        'sleep', '1',
        timeout = 2,
    )
    assert result.returncode == 0


@pytest.mark.slow
async def test_kill_process_ignoring_sigterm():
    from time import perf_counter
    start = perf_counter()
    result = await run_subprocess(
        'bash', '-c', 'trap "" SIGTERM ; sleep 1',
        timeout = 0.1,
        termination_grace = 0.1,
    )
    elapsed = perf_counter() - start
    assert elapsed >= .2, 'process ignoring SIGTERM must only be killed after timeout + termination grace mark'
    assert elapsed < 1, 'process must be killed before 1s mark where it would have terminated by itself'


@pytest.mark.slow
async def test_slow_but_not_idle_ok():
    result = await run_subprocess(
        'bash', '-c',
        'for ((i=0; i<5; i++)); do echo "$i"; sleep ."$i"; done',
        idle_timeout = .5,
    )
    assert result.returncode == 0
    assert result.stdout == [f'{i}\n' for i in range(5)]


@pytest.mark.slow
async def test_idle_timeout():
    result = await run_subprocess(
        'bash', '-c',
        'for ((i=0; i<5; i++)); do echo "$i"; sleep ."$i"; done',
        idle_timeout = .15,
    )
    assert result.stdout == [f'{i}\n' for i in range(3)], 'must return stdout captured so far before idle timeout when trying to sleep for 2 seconds'
    assert isinstance(result.exception, TimeoutError)
