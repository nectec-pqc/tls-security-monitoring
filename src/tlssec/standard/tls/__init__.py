"""Static information about TLS key establishment mechanism.

Sourced from https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
"""
# TODO: Add other TLS parameter information
# TODO: Create code to automatically update from XML version of the sourced data


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
