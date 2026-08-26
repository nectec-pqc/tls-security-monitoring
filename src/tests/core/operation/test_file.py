from pathlib import Path

import pytest

from tlssec.core.operation.file import external_document_loader


@pytest.mark.parametrize(
    'path, expected_type',
    [
        pytest.param(*x, id = x[0])
        for x in [
            (
                'core/testssl/result_cases/current_openssl_server/success.pretty.json',
                'testssl-pretty',
            ),
            (
                'core/testssl/result_cases/current_openssl_server/idle_timeout.pretty.json',
                'testssl-pretty',
            ),
            (
                'core/sshaudit/result_cases/openssh_server.json',
                'ssh-audit',
            ),
            (
                'core/nmap/result_cases/current_openssl_server/success.nmap.xml',
                'nmap',
            ),
        ]
    ],
)
def test_load_external_document(
    path, expected_type,
    tests_root,
):
    path = tests_root / path
    filetype, doc = external_document_loader.run(path)
    assert filetype == expected_type
