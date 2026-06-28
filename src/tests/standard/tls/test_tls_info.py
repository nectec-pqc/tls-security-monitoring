import pytest

import tlssec.standard as standard


def test_compile_cipher_names():
    from pathlib import Path
    import pandas as pd
    path = Path(standard.tls.__file__).parent / 'openssl_cipher_names_from_manual/cipher-names.csv'
    df = pd.read_csv(path, names = ['tls','openssl'])
    assert len(df.index) >= 1
    df['symenc'] = df.openssl.str.extract(
        standard.tls.SYMENC_IN_OPENSSL
    )
    df.symenc = df.symenc.str.replace('_', '', regex = False)
    unclassified = df[df.symenc.isna()]
    assert len(unclassified.index) <= 12, (
        'There shuold be no more than this many names that we can not identify symmetric encryption inside.'
        ' Some of these really do not contain symmetric encryption, but some is just unrecognized.'
    )
