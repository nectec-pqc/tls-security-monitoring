import asyncio

import pytest


def test_call_testssl():
    async def call() -> str | None:
        proc = await asyncio.create_subprocess_exec(
            'testssl', '--help',
            stdout = asyncio.subprocess.PIPE,
            stderr = asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(
                proc.communicate(),
                timeout = 1,
            )
            return out.decode()
        except TimeoutError:
            try:
                proc.kill()
            except OSError:
                pass
            await proc.wait()
        return

    result = asyncio.run(call())
    assert 'testssl [options] <URI>' in result
