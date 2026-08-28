from contextlib import nullcontext
from pathlib import Path

import pytest

from tlssec.core.operation.file import external_document_loader
from tlssec.task import AllAlternativesFailledError


@pytest.mark.parametrize(
    'path, expectation',
    [
        pytest.param(*x, id = x[0])
        for x in [
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
                'core/nmap/result_cases/current_openssl_server/success.nmap.xml',
                nullcontext('nmap'),
            ),
        ]
    ],
)
def test_load_external_document(
    path, expectation,
    tests_root,
):
    path = tests_root / path
    with expectation as expected_type:
        filetype, doc = external_document_loader.run(path)
        assert filetype == expected_type
