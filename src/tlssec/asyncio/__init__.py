import asyncio
from subprocess import CompletedProcess


async def read_stream(
    stream,
    idle_timeout = 10,
) -> list[str]:
    lines = []
    while True:
        line = await asyncio.wait_for(
            stream.readline(),
            timeout = idle_timeout,
        )
        if line == b'':
            break
        lines.append(line.decode())
    return lines


async def run_subprocess(
    *args,
    stdout = asyncio.subprocess.PIPE,
    stderr = asyncio.subprocess.PIPE,
    timeout = 180,
    idle_timeout = 10,
    termination_grace = 1,
    **kwargs,
) -> CompletedProcess | None:
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
    """
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout = stdout,
            stderr = stderr,
            **kwargs,
        )
        async with asyncio.timeout(timeout):
            out, err = await asyncio.gather(
                read_stream(proc.stdout, idle_timeout = idle_timeout),
                read_stream(proc.stderr, idle_timeout = None),
            )
            await proc.wait()
        return CompletedProcess(
            args = args,
            returncode = proc.returncode,
            # TODO: allow returning collection of lines directly
            stdout = ''.join(out),
            stderr = ''.join(err),
        )
    except Exception as e:
        # TODO: should return output captured so far
        # TODO: should return exception as value
        return
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
