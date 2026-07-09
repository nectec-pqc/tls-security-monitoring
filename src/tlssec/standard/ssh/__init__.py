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


quantum_safe_encs = {
    'AEAD_AES_256_GCM',
    'AEAD_CAMELLIA_256_GCM',
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
