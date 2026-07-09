import pytest

from ssh_audit.ssh2_kexdb import SSH2_KexDB

import tlssec.standard as standard
from tlssec.core.ssh_audit import SshAudit


def test_ssh_audit_db_agree_on_kem():
    for name in standard.ssh.quantum_safe_kems:
        ssh_audit_entry = SshAudit.lookup_ssh_audit_db('kex', name)
        assert ssh_audit_entry is not None, 'Every QS KEM name in our DB should also appear in ssh-audit DB'
        assert SSH2_KexDB.WARN_NOT_PQ_SAFE not in ssh_audit_entry.warnings
