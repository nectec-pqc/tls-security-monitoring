import asyncio
from subprocess import CompletedProcess


async def run_subprocess(
    *args,
    stdout = asyncio.subprocess.PIPE,
    stderr = asyncio.subprocess.PIPE,
    # in seconds
    timeout = 180,
    termination_grace = 1,
    **kwargs,
) -> CompletedProcess | None:
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout = stdout,
            stderr = stderr,
            **kwargs,
        )
        # TODO: timeout per stdout line
        out, err = await asyncio.wait_for(
            proc.communicate(),
            timeout = timeout,
        )
        return CompletedProcess(
            args = args,
            returncode = proc.returncode,
            stdout = out.decode(),
            stderr = err.decode(),
        )
    except Exception:
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
