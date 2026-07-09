import pytest

from ssh_audit.ssh2_kexdb import SSH2_KexDB

import tlssec.standard as standard
from tlssec.core.ssh_audit import SshAudit


def test_ssh_audit_db_agree_on_kem():
    for name in standard.ssh.quantum_safe_kems:
        ssh_audit_entry = SshAudit.lookup_ssh_audit_db('kex', name)
        assert ssh_audit_entry is not None, 'Every QS KEM name in our DB should also appear in ssh-audit DB'
        assert SSH2_KexDB.WARN_NOT_PQ_SAFE not in ssh_audit_entry.warnings


def test_ssh_audit_db_agree_on_enc():
    ssh_audit_safe_encs = {
        name: record
        for name, raw_record in SSH2_KexDB.MASTER_DB['enc'].items()
        for record in (SshAudit.DbRecord(*raw_record),)
        if (
            not record.failures
            and SSH2_KexDB.WARN_CIPHER_MODE not in record.warnings
        )
    }
    for name in standard.ssh.quantum_safe_encs:
        assert name in ssh_audit_safe_encs


def test_ssh_audit_db_agree_on_host_key_algo():
    ssh_audit_safe_host_key_algos = {
        name: record
        for name, raw_record in SSH2_KexDB.MASTER_DB['key'].items()
        for record in (SshAudit.DbRecord(*raw_record),)
        if (
            not record.failures
            and (
                SSH2_KexDB.INFO_NIST_PQC_LEVEL_2 in record.infos
                or SSH2_KexDB.INFO_NIST_PQC_LEVEL_3 in record.infos
                or SSH2_KexDB.INFO_NIST_PQC_LEVEL_5 in record.infos
            )
        )
    }
    for name in standard.ssh.quantum_safe_host_key_algos:
        assert name in ssh_audit_safe_host_key_algos
