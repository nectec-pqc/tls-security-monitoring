from contextlib import nullcontext
import json
from pathlib import Path

import pytest
import yaml

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
        doc = filetype_registry.load(path)
        assert doc.kind == 'external'
        assert doc.data.type == expected_type


@pytest.mark.parametrize(
    'path',
    [
        'core/testssl/result_cases/minihttp/1cert.pretty.json',
        'core/ssh_audit/result_cases/successful_scan_fail_audit.ssh_audit.json',
        'core/nmap/result_cases/success_find_both_ssh_and_ssl.nmap.xml',
    ],
)
def test_roundtrip_wrapped_external_document(
    path,
    tests_root,
    filetype_registry,
):
    path = tests_root / path
    doc = filetype_registry.load(path)
    serialized = doc.dump()
    reloaded_doc = filetype_registry.load(serialized)
    assert doc == reloaded_doc


def test_nmap_specific_invalidation(
    tests_root,
    filetype_registry,
):
    path = tests_root / 'core/nmap/result_cases/success_find_both_ssh_and_ssl.nmap.xml'
    valid = filetype_registry.load(path)

    invalid = valid.model_copy(deep = True)
    invalid.data.soup.find('nmaprun').name = 'notnmaprun'
    invalid.data.content = str(invalid.data.soup)

    with pytest.raises(AllAlternativesFailledError) as excinfo_invalid_content:
        reloaded_from_invalid_content = filetype_registry.load(invalid.data.content)
    assert excinfo_invalid_content.group_contains(ValueError, match = 'missing `nmaprun` tag')

    with pytest.raises(AllAlternativesFailledError) as excinfo_invalid_doc:
        reloaded_from_invalid_doc = filetype_registry.load(invalid.dump())
    assert excinfo_invalid_doc.group_contains(ValueError, match = 'missing `nmaprun` tag')


def test_testssl_specific_invalidation(
    tests_root,
    filetype_registry,
):
    path = tests_root / 'core/testssl/result_cases/no_service.pretty.json'
    valid = filetype_registry.load(path)

    invalid = valid.model_copy(deep = True)
    del invalid.data.content['scanResult']

    with pytest.raises(AllAlternativesFailledError) as excinfo_invalid_content:
        reloaded_from_invalid_content = filetype_registry.load(
            json.dumps(invalid.data.content)
        )
    assert excinfo_invalid_content.group_contains(ValueError, match = 'testssl --json-pretty')

    with pytest.raises(AllAlternativesFailledError) as excinfo_invalid_doc:
        reloaded_from_invalid_doc = filetype_registry.load(invalid.dump())
    assert excinfo_invalid_doc.group_contains(ValueError, match = 'testssl --json-pretty')


def test_ssh_audit_specific_invalidation(
    tests_root,
    filetype_registry,
):
    path = tests_root / 'core/ssh_audit/result_cases/successful_scan_fail_audit.ssh_audit.json'
    valid = filetype_registry.load(path)

    invalid = valid.model_copy(deep = True)
    del invalid.data.content['enc']

    with pytest.raises(AllAlternativesFailledError) as excinfo_invalid_content:
        reloaded_from_invalid_content = filetype_registry.load(
            json.dumps(invalid.data.content)
        )
    assert excinfo_invalid_content.group_contains(ValueError, match = 'ssh-audit --json')

    with pytest.raises(AllAlternativesFailledError) as excinfo_invalid_doc:
        reloaded_from_invalid_doc = filetype_registry.load(invalid.dump())
    assert excinfo_invalid_doc.group_contains(ValueError, match = 'ssh-audit --json')
