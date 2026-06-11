import asyncio
from dataclasses import dataclass


@dataclass
class CompletedProcess:
    args: list[str]
    returncode: int | None
    stdout: list[str]
    stderr: list[str]
    exception: Exception | None = None


async def read_stream(
    stream,
    buffer = None,
    idle_timeout = 10,
) -> list[str]:
    """Read stream line-by-line with idle timeout"""
    if buffer is None:
        buffer = []
    while True:
        line = await asyncio.wait_for(
            stream.readline(),
            timeout = idle_timeout,
        )
        if line == b'':
            break
        buffer.append(line.decode())
    return buffer


async def run_subprocess(
    *args,
    # TODO: test other choices such as: file, None, devnull
    stdout = asyncio.subprocess.PIPE,
    stderr = asyncio.subprocess.PIPE,
    timeout = 360,
    idle_timeout = 30,
    termination_grace = 1,
    **kwargs,
) -> CompletedProcess:
    """Run subprocess asynchronously with timeout controls

    Pass parameters through to `asyncio.create_subprocess_exec`
    unless it's the following additional ones.

    Parameters
    ----------
    timeout
        Total time in seconds allowed for the whole subprocess.
    idle_timeout
        Subprocess must write a new line to stdout within this number of
        seconds or it will be terminated.
    termination_grace
        Seconds allowed for process to act on SIGTERM before sending SIGKILL.

    Returns
    -------
    CompletedProcess
        If the process has started, return CompletedProcess object containing
        captured output so far and exception that terminated the process if any.

        If process has not yet started due to some exception,
        that exception will be propagated out.
    """
    proc = None
    out = []
    err = []
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout = stdout,
            stderr = stderr,
            **kwargs,
        )
        async with asyncio.timeout(timeout):
            await asyncio.gather(
                read_stream(proc.stdout, buffer = out, idle_timeout = idle_timeout),
                read_stream(proc.stderr, buffer = err, idle_timeout = None),
            )
            await proc.wait()
        return CompletedProcess(
            args = args,
            returncode = proc.returncode,
            stdout = out,
            stderr = err,
        )
    except Exception as e:
        if proc is None:
            raise

        return CompletedProcess(
            args = args,
            returncode = proc.returncode, # Should typically be None
            stdout = out,
            stderr = err,
            exception = e,
        )
    finally:
        if (
            # Subprocess has started
            proc is not None
            # and is yet to be completed
            and proc.returncode is None
        ):
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout = termination_grace)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
