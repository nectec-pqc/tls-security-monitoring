import asyncio
from pathlib import Path

import pytest

from tlssec.core.testssl import Testssl


@pytest.fixture(scope = 'module')
def testssl():
    yield Testssl()
    # TODO: kill all tasks


async def test_call_testssl(testssl):
    result = await testssl.call('--help', timeout = 1)
    assert result.returncode == 0
    assert any('testssl [options] <URI>' in line for line in result.stdout)


async def test_testssl_error(testssl):
    result = await testssl.call(
        '--this-option-is-invalid',
        timeout = 1,
    )
    assert result.returncode != 0


# NOTE: For other kind of scan target,
# we might need to install different version of openssl or nginx into test image.
# Or might even need to use separate container.
# TODO: get output line-by-line, timeout on not getting new line
@pytest.mark.slow
async def test_scan_local(testssl, current_openssl_server):
    result = await testssl.call(
        '--forward-secrecy', 'localhost:4433',
    )
    assert result.returncode == 0
    assert any('X25519MLKEM768' in line for line in result.stdout)


# TODO: Maybe create a command to generate test case file
# instead of piggybacking on test running infrastructure?
# TODO: Make proper tests for testssl json generation cases
@pytest.mark.skip(
    'Not a real test.'
    ' For producing test case file used in other tests.'
)
@pytest.mark.slow
async def test_generate_testssl_json(testssl, current_openssl_server):
    import json
    out_dir = Path(__file__).parent / 'result_cases/current_openssl_server'
    out_dir.mkdir(parents = True, exist_ok = True)
    tmp_file = out_dir / 'tmp.json'
    tmp_file.unlink(missing_ok = True)

    for testssl_opts, call_kwargs, filename in [
        (
            ('--jsonfile', str(tmp_file)),
            {},
            'success.json',
        ),
        (
            ('--jsonfile-pretty', str(tmp_file)),
            {},
            'success.pretty.json',
        ),
        (
            ('--jsonfile', str(tmp_file)),
            {'idle_timeout': 10},
            'idle_timeout.json',
        ),
        # FIXME: Next process sometimes get stuck after
        # previous process idle_timeout
        (
            ('--jsonfile-pretty', str(tmp_file)),
            {'idle_timeout': 10},
            'idle_timeout.pretty.json',
        ),
    ]:
        result = await testssl.call(
            *testssl_opts, 'localhost:4433',
            cwd = out_dir,
            **call_kwargs,
        )

        with open(tmp_file) as f:
            # FIXME: testssl sometimes produce invalid JSON.
            # I have seen --json mode produce the last "scanTime" item
            # outside of its main list.
            content = json.load(f)
        with open(out_dir / filename, 'w') as f:
            json.dump(content, f, indent = 2)

        tmp_file.unlink(missing_ok = True)
