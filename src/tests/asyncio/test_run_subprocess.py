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
    assert result.stdout == f'{cwd}\n'


async def test_success_with_stderr():
    result = await run_subprocess(
        'bash', '-c', 'echo info 1>&2',
    )
    assert result.returncode == 0
    assert 'info' in result.stderr


async def test_false():
    result = await run_subprocess('false')
    assert result.returncode != 0
    assert result.stdout == ''
    assert result.stderr == ''


async def test_failure_to_create_subprocess():
    result = await run_subprocess('not-a-real-command')
    assert result is None


@pytest.mark.slow
async def test_timeout_error():
    result = await run_subprocess(
        'sleep', '1',
        timeout = .5,
    )
    assert result is None


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
