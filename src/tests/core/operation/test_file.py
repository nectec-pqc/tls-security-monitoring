from pathlib import Path

import pytest

from tlssec.core.operation.file import external_document_loader


@pytest.mark.parametrize(
    'path, expected_type',
    [
        pytest.param(*x, id = x[0])
        for x in [
            (
                'testssl/result_cases/current_openssl_server/success.pretty.json',
                'testssl-pretty',
            ),
            (
                'testssl/result_cases/current_openssl_server/idle_timeout.pretty.json',
                'testssl-pretty',
            ),
            (
                'sshaudit/result_cases/openssh_server.json',
                'ssh-audit',
            ),
            (
                'nmap/result_cases/current_openssl_server/success.nmap.xml',
                'nmap',
            ),
        ]
    ],
)
def test_load_external_document(path, expected_type):
    # Where tests.core module is located
    base_path = Path(__file__).parent.parent
    path = base_path / path
    filetype, doc = external_document_loader.run(path)
    assert filetype == expected_type
