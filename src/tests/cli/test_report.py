import os

import pytest

from tlssec.cli import cli


@pytest.fixture
def set_cwd(cli_runner, cache_dir, request):
    """Set current working directory for test running report production CLI.

    - All tests share a base directory, but each has a subdirectory named after
      its parameterization ID.
    - The directory is not cleaned up after test to allow
      easy manual inspection after the tests ran.
    """
    base = cache_dir / 'report' / request.node.callspec.id
    base.mkdir(parents = True, exist_ok = True)

    old_cwd = os.getcwd()
    os.chdir(base)
    try:
        yield base
    finally:
        os.chdir(old_cwd)


@pytest.mark.parametrize(
    'sources',
    [
        pytest.param(
            [
                'core/testssl/result_cases/current_openssl_server/success.pretty.json',
                'core/ssh_audit/result_cases/successful_scan_fail_audit.ssh_audit.json',
                'core/nmap/result_cases/success_find_both_ssh_and_ssl.nmap.xml',
            ],
            # NOTE: Parameter ID will be used to name output directory.
            # Take care to use valid filesystem name.
            id = 'port 2222 ssh + port 4433 tls',
        ),
    ],
)
def test_report(set_cwd, cli_runner, tests_root, sources):
    sources = [tests_root / x for x in sources]
    result = cli_runner.invoke(
        cli,
        [
            'adhoc', 'export-report',
            '--out', '.',
            *map(str, sources),
        ],
        catch_exceptions = False,
    )
    assert result.exit_code == 0
