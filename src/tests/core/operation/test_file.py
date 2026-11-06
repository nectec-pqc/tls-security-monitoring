from contextlib import nullcontext
from pathlib import Path

import pytest

from tlssec.core.operation.file import FiletypeRegistry
from tlssec.task import AllAlternativesFailledError


@pytest.fixture(scope = 'module')
def filetype_registry():
    return FiletypeRegistry()


@pytest.mark.parametrize(
    'path, expectation',
    [
        pytest.param(*x, id = x[0])
        for x in [
            (
                'core/testssl/result_cases/no_service.pretty.json',
                nullcontext('testssl-pretty'),
            ),
            (
                'core/testssl/result_cases/minihttp/no_tls.pretty.json',
                nullcontext('testssl-pretty'),
            ),
            (
                'core/testssl/result_cases/minihttp/1cert.pretty.json',
                nullcontext('testssl-pretty'),
            ),
            (
                'core/testssl/result_cases/minihttp/2certs.pretty.json',
                nullcontext('testssl-pretty'),
            ),
            (
                'core/testssl/result_cases/current_openssl_server/success.pretty.json',
                nullcontext('testssl-pretty'),
            ),
            (
                'core/testssl/result_cases/current_openssl_server/idle_timeout.pretty.json',
                nullcontext('testssl-pretty'),
            ),
            (
                'core/ssh_audit/result_cases/can_not_resolve_hostname.ssh_audit.json',
                pytest.raises(AllAlternativesFailledError),
            ),
            (
                'core/ssh_audit/result_cases/rejected_because_recent_connection_looks_like_scanner.ssh_audit.json',
                pytest.raises(AllAlternativesFailledError),
            ),
            (
                'core/ssh_audit/result_cases/successful_scan_fail_audit.ssh_audit.json',
                nullcontext('ssh-audit'),
            ),
            (
                'core/nmap/result_cases/success_find_ssl_only.nmap.xml',
                nullcontext('nmap'),
            ),
            (
                'core/nmap/result_cases/success_find_both_ssh_and_ssl.nmap.xml',
                nullcontext('nmap'),
            ),
        ]
    ],
)
def test_load_external_document(
    path, expectation,
    filetype_registry,
    tests_root,
):
    path = tests_root / path
    with expectation as expected_type:
        doc = filetype_registry.load_file(path)
        assert doc.kind == expected_type
