import asyncio
from pathlib import Path
from subprocess import CompletedProcess

import tlssec.core.model as m
from tlssec.asyncio import run_subprocess


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
        **kwargs,
    ) -> CompletedProcess | None:
        async with self.semaphore:
            return await run_subprocess('testssl', *args, **kwargs)

    async def scan(
        self,
        endpoint: m.Endpoint,
    ) -> m.Scan:
        # TODO: use self.call to actually do scan
        raise NotImplementedError
