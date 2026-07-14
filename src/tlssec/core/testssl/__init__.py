import os
import json
import asyncio
import ipaddress
import tempfile
from datetime import datetime
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

    # Map an endpoint's application_protocol (an nmap service name) to the value
    # testssl.sh expects for its `--starttls` option, used only for explicit /
    # STARTTLS endpoints (TLS negotiated after a plaintext handshake).
    #
    # Keys are nmap service names, covering both the `-sV` detection names
    # (nmap-service-probes -- e.g. XMPP is `xmpp` or `jabber`) and the
    # port-table names (nmap-services -- e.g. 5222 is `xmpp-client`). Values are
    # testssl's documented `--starttls` protocols (testssl.sh man page).
    # Implicit / wrapped-TLS service names (smtps, imaps, pop3s, ftps, ldaps)
    # are intentionally absent: those are scanned as implicit TLS, no --starttls.
    STARTTLS_PROTOCOLS = {
        'smtp': 'smtp',
        'submission': 'smtp',
        'lmtp': 'lmtp',
        'pop3': 'pop3',
        'imap': 'imap',
        'ftp': 'ftp',
        'telnet': 'telnet',
        'ldap': 'ldap',
        'irc': 'irc',
        'nntp': 'nntp',
        'sieve': 'sieve',
        'xmpp': 'xmpp',
        'jabber': 'xmpp',
        'xmpp-client': 'xmpp',
        'postgres': 'postgres',
        'postgresql': 'postgres',
        'mysql': 'mysql',
    }

    async def scan(
        self,
        endpoint: m.Endpoint,
    ) -> m.Scan:
        """Run testssl.sh against a single endpoint and return its result.

        testssl writes machine-readable output to a file (via ``--jsonfile-pretty``)
        rather than to stdout, so we point it at a throwaway temp file and read
        it back. Explicit (STARTTLS) endpoints are scanned with ``--starttls``
        using the protocol derived from ``application_protocol``.

        Raises
        ------
        ValueError
            If the endpoint has no host to scan, or is an explicit-TLS endpoint
            whose application protocol has no known ``--starttls`` mapping.
        RuntimeError
            If testssl was terminated (e.g. timeout) or produced no output.
        """
        host = endpoint.hostname or (
            str(endpoint.ip) if endpoint.ip is not None else None
        )
        if host is None:
            raise ValueError('endpoint has neither hostname nor ip to scan')
        target = f'{host}:{endpoint.port}'

        options = []
        if endpoint.tls_mode == m.TlsMode.explicit:
            starttls = self.STARTTLS_PROTOCOLS.get(
                (endpoint.application_protocol or '').lower()
            )
            if starttls is None:
                raise ValueError(
                    f'We cannot handle this protocol at the moment'
                    f'cannot scan STARTTLS endpoint {target}: no --starttls'
                    f' mapping for application protocol'
                    f' {endpoint.application_protocol!r}'
                )
            options += ['--starttls', starttls]

        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = Path(tmpdir) / 'result.json'
            start_time = datetime.now()
            completed = await self.call(
                '--jsonfile-pretty', str(json_path),
                *options,
                target,
            )
            time_taken = round((datetime.now() - start_time).total_seconds())

            if completed.exception is not None:
                raise RuntimeError(
                    f'testssl did not complete on {target}'
                ) from completed.exception

            try:
                with json_path.open() as f:
                    result = json.load(f)
            except FileNotFoundError as e:
                raise RuntimeError(
                    f'testssl produced no output for {target}'
                    f' (returncode={completed.returncode})'
                ) from e

        return m.Scan(
            result = result,
            scanner = m.Scanner.testssl,
            scanner_version = result.get('version') if isinstance(result, dict) else None,
            observed_ip = self._observed_ip(result),
            # testssl scans by hostname when available, sending it as SNI.
            sni = endpoint.hostname,
            start_time = start_time,
            time_taken = time_taken,
        )

    @staticmethod
    def _observed_ip(result) -> str | None:
        """The IP testssl actually connected to, from its scan result.

        This can differ from the endpoint's own IP when a hostname resolves to a
        different / rotating address than nmap saw (load balancer, round-robin
        DNS). Returns None if absent or not a valid IP.
        """
        if not isinstance(result, dict):
            return None
        scan_results = result.get('scanResult') or []
        if not scan_results:
            return None
        try:
            return str(ipaddress.ip_address(scan_results[0].get('ip')))
        except (ValueError, TypeError):
            return None

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
                    'key_establishment': {
                        'safe': set(),
                        'unsafe': set(),
                    },
                    'symmetric_encryption': {
                        'safe': set(),
                        'unsafe': set(),
                    },
                    'server_cert_signature': {},
                },
            }

            for fs_item in scan.get('fs', []):
                # NOTE: Repeated match on the same ID shouldn't exists, but if it does, the findings will be concatenated.
                match fs_item:
                    case {
                        'id': 'FS_KEMs' | 'FS_ECDHE_curves' | 'DH_groups' as item_id,
                        'finding': str(params),
                    }:
                        if item_id == 'DH_groups' and 'ffdhe' not in params:
                            # CAUTION: When testssl output DH_groups findings,
                            # the finding may not be a list of parameter names separated by spaces like other cases.
                            # This happen when DH group found is not one of RFC 7919.
                            # When this happens, the whole finding is a decription of DH group which may contain spaces inside.
                            # See https://github.com/testssl/testssl.sh/blob/9fdf8028baba86d83218db294a5776384ec8c332/testssl.sh#L11838-L11864
                            params = params.replace(' ', '_')
                        for param in params.split():
                            extract['qs']['key_establishment']['safe' if param in standard.tls.quantum_safe_kems else 'unsafe'].add(param)
                    case {'id': 'FS_ciphers', 'finding': str(ciphers)}:
                        for cipher in ciphers.split():
                            symenc = standard.tls.guess_symenc_from_openssl_cipher_name(cipher)
                            qs_safe = standard.tls.is_symenc_quantum_safe(symenc)
                            extract['qs']['symmetric_encryption']['safe' if qs_safe else 'unsafe'].add(symenc)

            for sd_item in scan.get('serverDefaults', []):
                match sd_item:
                    case {'id': 'cert_signatureAlgorithm', 'finding': str(algo)}:
                        extract['qs']['server_cert_signature']['algo'] = algo
                    case {'id': 'cert_keySize', 'finding': str(key_size)}:
                        extract['qs']['server_cert_signature']['key_size'] = key_size
            
            extracts.append(extract)

        return extracts
