import pytest

from ssh_audit.ssh2_kexdb import SSH2_KexDB

import tlssec.standard as standard


def test_ssh_audit_db_agreement():
    for name in standard.ssh.quantum_safe_kems:
        ssh_audit_entry = SSH2_KexDB.MASTER_DB['kex'].get(name, None)
        assert ssh_audit_entry is not None, 'Every QS KEM name in our DB should also appear in ssh-audit DB'
        warnings = (
            ssh_audit_entry[3]
            if len(ssh_audit_entry) >= 3 else
            []
        )
        assert SSH2_KexDB.WARN_NOT_PQ_SAFE not in warnings
