"""Static information about TLS key establishment mechanism.

Sources:

- https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
- https://docs.openssl.org/3.0/man1/openssl-ciphers/#cipher-suite-names
- `openssl ciphers -V -stdname`
- https://www.ssl.org/cipher-suite-mapping
"""
# TODO: Compile information from sources.
# Try to import programmatically, we will need to update and re-run the process.
# TODO: Create code to automatically update from XML version of the sourced data
import re


quantum_safe_kems = {
    'MLKEM512',
    'MLKEM768',
    'MLKEM1024',
    'SecP256r1MLKEM768',
    'X25519MLKEM768',
    'SecP384r1MLKEM1024',
    'curveSM2MLKEM768',
    'X25519Kyber768Draft00',
}


# Capture symmetric encryption name within openssl cipher suite names.
SYMENC_IN_OPENSSL = re.compile(
    r'(?:^|[-_])((?:AES|CAMELLIA|ARIA)_?\d*|CHACHA20|SEED|RC4|(?:3)?DES(?:-CBC3)?|SM4|IDEA)(?:$|[-_])'
    # FIXME: We are ignoring GOST suites. They have weird naming scheme.
    # In the end, this regex is just a heuristic, we should be relying on full lookup table where possible.
)

def guess_symenc_from_openssl_cipher_name(name: str) -> str | None:
    m = SYMENC_IN_OPENSSL.search(name)
    if m is None:
        return None
    symenc = m[1]
    # Normalize further where regex couldn't
    if symenc == 'DES-CBC3':
        symenc = '3DES'
    symenc = symenc.replace('_', '')
    return symenc


IS_SYMENC_QUANTUM_SAFE = {
    'AES256': True,
    'ARIA256': True,
    'CAMELLIA256': True,
    'CHACHA20': True,

    'AES128': False,
    'ARIA128': False,
    'CAMELLIA128': False,
    'SM4': False,
    'DES': False, #broken
    '3DES': False, #broken
    'RC4': False, #broken
    'SEED': False,
    'IDEA': False,
}


def is_symenc_quantum_safe(name: str) -> bool:
    return IS_SYMENC_QUANTUM_SAFE[name]
