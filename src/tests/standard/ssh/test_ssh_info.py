from ssh_audit.ssh2_kexdb import SSH2_KexDB

import tlssec.standard as standard
from tlssec.core.ssh_audit import SshAudit


def test_curated_pqc_algorithms_resolve_to_a_nist_level():
    # Guards drift between the curated sets and `nist_pqc_levels`: every PQC
    # name we claim is quantum-safe must resolve to a NIST category.
    for name in standard.ssh.quantum_safe_kems | standard.ssh.quantum_safe_host_key_algos:
        assert standard.ssh.nist_level(name) in (1, 2, 3, 5), name
    # ...and classical algorithms must never be tagged as PQC.
    for name in ('curve25519-sha256', 'ecdh-sha2-nistp256', 'ssh-ed25519', 'rsa-sha2-512'):
        assert standard.ssh.nist_level(name) is None, name


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


