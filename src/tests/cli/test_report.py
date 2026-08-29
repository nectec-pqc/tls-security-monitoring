import shutil

import pytest

from tlssec.cli import cli


@pytest.fixture(autouse = True)
def set_cli_cwd(cli_runner, cache_dir):
    base = cache_dir / 'report'
    base.mkdir(parents = True, exist_ok = True)
    with cli_runner.isolated_filesystem(base) as cwd:
        yield cwd
    shutil.rmtree(cwd)


def test_report(cli_runner, tests_root):
    sources = [
        'core/testssl/result_cases/current_openssl_server/success.pretty.json',
        'core/ssh_audit/result_cases/successful_scan_fail_audit.ssh_audit.json',
        'core/nmap/result_cases/success_find_both_ssh_and_ssl.nmap.xml',
    ]
    sources = [tests_root / x for x in sources]
    result = cli_runner.invoke(
        cli,
        ['adhoc', 'export-report', *map(str, sources)],
        catch_exceptions = False,
    )
    assert result.exit_code == 0
