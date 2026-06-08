import pytest
from pathlib import Path

from tlssec.asyncio import run_subprocess


async def test_success_pwd():
    cwd = Path(__file__).parent
    result = await run_subprocess(
        'pwd',
        cwd = cwd,
    )
    assert result.returncode == 0
    assert result.stdout == f'{cwd}\n'


async def test_false():
    result = await run_subprocess('false')
    assert result.returncode != 0
    assert result.stdout == ''
