import os
from pathlib import Path

import yaml

import tlssec.standard as standard


class SshAudit:
    """ssh-audit wrapper"""

    # TODO: Try calling ssh-audit via python API directly
    # instead of having to write result to file first.

    @classmethod
    def extract_json(
        cls,
        source: dict | list | os.PathLike,
    ) -> dict:
        if not isinstance(source, dict | list):
            with open(source) as f:
                source = yaml.safe_load(f)

        # FIXME ssh-audit only record scan target as unparsed str in json.
        # To re-parse the target specification, one must follow the logic in:
        # https://github.com/jtesta/ssh-audit/blob/c63c4a712be1ddae051c806a17171d661d352ff8/src/ssh_audit/utils.py#L132
        #
        # For now, we just assume it's always `{ip}:{port}`
        ip, port = source['target'].split(':')
        
        extract = {
            'ip': ip,
            'port': port,
            'raw': source,
            'qs': {
                'key_establishment': {
                    'safe': set(),
                    'unsafe': set(),
                },
                'symmetric_encryption': {
                    'safe': set(),
                    'unsafe': set(),
                },
                'server_cert_signature': {
                    'safe': set(),
                    'unsafe': set(),
                },
            },
        }

        for item in source['kex']:
            # NOTE: ignore notes in file, trust "current" classification of
            # algorithm in library instead of one recorded previously.
            safe = item['algorithm'] in standard.ssh.quantum_safe_kems
            extract['qs']['key_establishment']['safe' if safe else 'unsafe'].add(item['algorithm'])

        # TODO: populate symmetric_encryption and server_cert_signature
        breakpoint()

        return extract
