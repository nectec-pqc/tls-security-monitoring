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
    r'(?:^|[-_])((?:AES|CAMELLIA|ARIA)_?\d*|CHACHA20|SEED|RC4|DES|SM4|IDEA)(?:$|[-_])'
    # FIXME: We are ignoring GOST suites. They have weird naming scheme.
    # In the end, this regex is just a heuristic, we should be relying on full lookup table where possible.
)
