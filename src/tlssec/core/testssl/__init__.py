import asyncio
from pathlib import Path
from dataclasses import dataclass

import tlssec.core.model as m


@dataclass
class CompletedTestssl:
    # Similar to subprocess.CompletedProcess
    returncode: int
    stdout: str
    stderr: str


class Testssl:
    """testssl.sh wrapper

    - with asyncio concurrency
    - with maximum concurrency control
    """
    # Not a pytest test
    __test__ = False

    def __init__(
        self,
        concurrency: int = 128,
    ):
        self.semaphore = asyncio.Semaphore(concurrency)

    async def call(
        self,
        *args,
        # in seconds
        timeout: int = 180,
    ) -> CompletedTestssl | None:
        async with self.semaphore:
            proc = await asyncio.create_subprocess_exec(
                'testssl', *args,
                stdout = asyncio.subprocess.PIPE,
                stderr = asyncio.subprocess.PIPE,
            )
            try:
                # TODO: timeout per stdout line
                out, err = await asyncio.wait_for(
                    proc.communicate(),
                    timeout = timeout,
                )
                return CompletedTestssl(
                    returncode = proc.returncode,
                    stdout = out.decode(),
                    stderr = err.decode(),
                )
            except TimeoutError:
                # TODO: handle other exceptions too
                # TODO: try SIGTERM frist
                try:
                    proc.kill()
                except OSError:
                    pass
                await proc.wait()
                # TODO: should return output captured so far
                return None

    async def scan(
        self,
        endpoint: m.Endpoint,
    ) -> m.Scan:
        # TODO: use self.call to actually do scan
        raise NotImplementedError
