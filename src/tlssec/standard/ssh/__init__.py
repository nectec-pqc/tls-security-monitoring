"""Static information about openssh standard

Sources:
- ```
  ssh -Q help
  ssh -Q kex
  ssh -Q key
  ssh -Q cipher
  ```
  etc.
- https://www.openssh.org/pq.html
- https://www.openssh.org/specs.html
- [ssh-audit's database](https://github.com/jtesta/ssh-audit/blob/master/src/ssh_audit/ssh2_kexdb.py)
  The formatting is too messy to be used directly. (They don't follow their own type hints)
  But should be good to use as one of the sources.
- https://ssh-comparison.quendi.de/comparison/cipher.html
"""


# Algorithm names must be in the same format used by `ssh -Q kex`
quantum_safe_kems = {
    'mlkem768x25519-sha256',
    'mlkem768nistp256-sha256',
    'mlkem1024nistp384-sha384',
    'sntrup761x25519-sha512',
    'sntrup761x25519-sha512@openssh.com',
}
# Not real kem algorithm, just informational marker
pseudo_kems = {
    'ext-info-c',
    'ext-info-s',
    'kex-strict-c-v00@openssh.com',
    'kex-strict-s-v00@openssh.com',
}


quantum_safe_encs = {
    'AEAD_AES_256_GCM',
    # NOTE: RFC 5647 defines only the AES variants of the `AEAD_*` names, so
    # there is no `AEAD_CAMELLIA_256_GCM` in SSH; Camellia appears as
    # `camellia256-ctr` below.
    'aes256-ctr',
    'aes256-gcm',
    'aes256-gcm@openssh.com',
    'camellia256-ctr',
    'camellia256-ctr@openssh.org',
    'chacha20-poly1305',
    'chacha20-poly1305@openssh.com',
    'twofish256-ctr',
    'twofish256-gcm@libassh.org',
    # FIXME: Find proper reference of key size of `twofish-ctr`
    # and decide if it is quantum-safe.
}


quantum_safe_host_key_algos = {
    'mldsa-44',
    'mldsa-65',
    'mldsa-87',
    'ssh-mldsa-44',
    'ssh-mldsa-65',
    'ssh-mldsa-87',
    'ssh-mldsa44',
    'ssh-mldsa44-ed25519@openssh.com',
    'ssh-mldsa65',
    'ssh-mldsa87',
}


# PQC family -> NIST security category (FIPS 203 ML-KEM, FIPS 204 ML-DSA).
# Single source of truth for SSH PQC levels: the CBOM builder reads it to tag
# `nistQuantumSecurityLevel` on both key exchange and host key components.
nist_pqc_levels = {
    'mlkem1024': 5,
    'mlkem768': 3,
    'mlkem512': 1,
    'mldsa87': 5,
    'mldsa65': 3,
    'mldsa44': 2,
    # NTRU Prime was never selected by NIST so it has no official category;
    # 2 is the commonly cited equivalent strength.
    'sntrup4591761': 2,
    'sntrup761': 2,
    # Pre-standardization Kyber names, still offered by older servers.
    'kyber1024': 5,
    'kyber768': 3,
    'kyber512': 1,
}


def nist_level(algorithm: str) -> int | None:
    """NIST PQC category of an ssh algorithm name, or None if it is not PQC.

    Names are hybrids carrying vendor suffixes and inconsistent hyphenation
    (``mlkem768x25519-sha256``, ``ssh-mldsa44-ed25519@openssh.com``,
    ``mldsa-65``), so the family is matched against the alphanumeric-only form
    of the name rather than looked up exactly.
    """
    normalized = ''.join(c for c in algorithm.lower() if c.isalnum())
    for family, level in nist_pqc_levels.items():
        if family in normalized:
            return level
    return None
