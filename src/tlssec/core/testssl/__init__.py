import os
import asyncio
from pathlib import Path

import yaml

import tlssec.core.model as m
from tlssec.asyncio import run_subprocess, CompletedProcess
import tlssec.standard as standard


class Testssl:
    """testssl.sh wrapper

    - with asyncio concurrency
    - with maximum concurrency control
    """
    # Not a pytest test
    __test__ = False

    def __init__(
        self,
        concurrency: int | asyncio.Semaphore = 128,
    ):
        if isinstance(concurrency, asyncio.Semaphore):
            self.semaphore = concurrency
        else:
            self.semaphore = asyncio.Semaphore(concurrency)

    async def call(
        self,
        *args,
        **kwargs,
    ) -> CompletedProcess:
        async with self.semaphore:
            return await run_subprocess('testssl', *args, **kwargs)

    async def scan(
        self,
        endpoint: m.Endpoint,
    ) -> m.Scan:
        # TODO: use self.call to actually do scan
        raise NotImplementedError

    @classmethod
    def extract_json(
        cls,
        source: dict | list | os.PathLike,
    ) -> dict:
        if not isinstance(source, dict | list):
            with open(source) as f:
                source = yaml.safe_load(f)
        if isinstance(source, list):
            raise ValueError(
                'This might because the file is produced by testssl --json instead of --json-pretty.'
                ' We do not support --json format yet.'
            );

        extracts = []
        for scan in source['scanResult']:
            extract = {
                'ip': scan['ip'],
                'port': scan['port'],
                'qs': {
                    'symmetric_encryption': {
                        'safe': [],
                        'unsafe': [],
                    },
                    'server_cert_signature': {},
                },
            }

            fs_kem = [
                fs_item
                for fs_item in scan.get('fs', [])
                if fs_item.get('id', None) == 'FS_KEMs'
            ]
            match fs_kem:
                case []:
                    extract['qs']['key_establishment'] = None
                case [fs_kem]:
                    kems = fs_kem.get('finding', '').split()
                    qs_kems = standard.tls.quantum_safe_kems.intersection(kems)
                    extract['qs']['key_establishment'] = qs_kems
                case _:
                    raise AssertionError('Each testssl `scanResult` should contain no more than one FS_KEMs item')

            for fs_item in scan.get('fs', []):
                match fs_item:
                    case {'id': 'FS_ciphers', 'finding': str(ciphers)}:
                        # NOTE: Multiple FS_ciphers shouldn't exists, but if it does, the result will be concatenated.
                        for cipher in ciphers.split():
                            symenc = standard.tls.guess_symenc_from_openssl_cipher_name(cipher)
                            qs_safe = standard.tls.is_symenc_quantum_safe(symenc)
                            extract['qs']['symmetric_encryption']['safe' if qs_safe else 'unsafe'].append(symenc)

            for sd_item in scan.get('serverDefaults', []):
                match sd_item:
                    case {'id': 'cert_signatureAlgorithm', 'finding': str(algo)}:
                        extract['qs']['server_cert_signature']['algo'] = algo
                    case {'id': 'cert_keySize', 'finding': str(key_size)}:
                        extract['qs']['server_cert_signature']['key_size'] = key_size
            
            extracts.append(extract)
        return extracts
