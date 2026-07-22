import asyncio
import json
from datetime import datetime
from importlib.metadata import version, PackageNotFoundError

import tlssec.core.model as m
from tlssec.asyncio import run_subprocess, CompletedProcess


def _tool_version():
    try:
        return version('ssh-audit')
    except PackageNotFoundError:
        return None


class SshAudit:
    """ssh-audit wrapper

    - with asyncio concurrency
    - with maximum concurrency control

    Mirrors :class:`~tlssec.core.testssl.Testssl`, but ssh-audit writes its
    JSON report to stdout and exits non-zero whenever it merely flags weak
    algorithms, so a non-zero return code is expected and is not treated as a
    failure -- only a killed process or unparseable output is.
    """
    def __init__(
        self,
        concurrency: int | asyncio.Semaphore = 128,
    ):
        if isinstance(concurrency, asyncio.Semaphore):
            self.semaphore = concurrency
        else:
            self.semaphore = asyncio.Semaphore(concurrency)

    async def call(
        self,
        *args,
        **kwargs,
    ) -> CompletedProcess:
        async with self.semaphore:
            return await run_subprocess('ssh-audit', *args, **kwargs)

    async def scan(
        self,
        endpoint: m.Endpoint,
    ) -> m.Scan:
        """Run ssh-audit against a single endpoint and return its result.

        Raises
        ------
        ValueError
            If the endpoint has no host to scan.
        RuntimeError
            If ssh-audit was terminated (e.g. timeout) or produced no
            parseable JSON.
        """
        host = endpoint.hostname or (
            str(endpoint.ip) if endpoint.ip is not None else None
        )
        if host is None:
            raise ValueError('endpoint has neither hostname nor ip to scan')
        target = f'{host}:{endpoint.port}'

        start_time = datetime.now()
        completed = await self.call('--json', '-p', str(endpoint.port), host)
        time_taken = round((datetime.now() - start_time).total_seconds())
          
        if completed.exception is not None:
            raise RuntimeError(
                f'ssh-audit did not complete on {target}'
            ) from completed.exception
            
        try:
            result = json.loads(''.join(completed.stdout))
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f'ssh-audit produced no parseable JSON for {target}'
                f' (returncode={completed.returncode})'
            ) from e
          
        return m.Scan(
            result = result,
            scanner = m.Scanner.ssh_audit,
            scanner_version = _tool_version(),
            start_time = start_time,
            time_taken = time_taken,
        )
