import subprocess
from pathlib import Path

import pytest
import ssh_audit.exitcodes

from tlssec.core.ssh_audit import SshAudit


# TODO: add success cases
@pytest.mark.parametrize(
    'name, target, expected_exitcode',
    [
        pytest.param(*x, id = x[0])
        for x in (
            (
                'successful_scan_fail_audit',
                '127.0.0.1:2222',
                ssh_audit.exitcodes.FAILURE,
            ),
            # FIXME: This only create connection error as intended if
            # it is called right after the above test case.
            (
                'rejected_because_recent_connection_looks_like_scanner',
                '127.0.0.1:2222',
                ssh_audit.exitcodes.CONNECTION_ERROR,
            ),
            (
                'can_not_resolve_hostname',
                'host-not-exists',
                ssh_audit.exitcodes.CONNECTION_ERROR,
            ),
        )
    ],
)
@pytest.mark.regen_case
async def test_generate_ssh_audit_json(
    current_openssh_server,
    name,
    target,
    expected_exitcode,
):
    out_path = Path(__file__).parent / f'result_cases/{name}.ssh_audit.json'
    out_path.parent.mkdir(parents = True, exist_ok = True)

    completed_process = await SshAudit.scan(target)
    assert completed_process.returncode == expected_exitcode

    with open(out_path, 'w') as f:
        # TODO: prettify JSON ?
        # Problem: Error messages are not written inside JSON format.
        for line in completed_process.stdout:
            f.write(line)
