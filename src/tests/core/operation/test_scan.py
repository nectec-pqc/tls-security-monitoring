import asyncio

import pytest


def test_call_testssl():
    async def call():
        proc = await asyncio.create_subprocess_exec(
            'testssl', '--help',
            stdout = asyncio.subprocess.PIPE,
            stderr = asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        return out.decode()

    result = asyncio.run(call())
    assert 'testssl [options] <URI>' in result
