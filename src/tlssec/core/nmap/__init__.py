import os
import asyncio
import tempfile
from pathlib import Path
from datetime import datetime
import re
import unicodedata
from typing import TextIO

import bs4

import tlssec.core.model as m
from tlssec.asyncio import run_subprocess, CompletedProcess


class Nmap:
    """nmap wrapper"""

    # Ports and service names that speak TLS directly (implicit / wrapped TLS)
    # rather than negotiating it via STARTTLS. Service names are nmap's
    # port-table names (nmap-services); ports are the IANA-registered
    # implicit-TLS ports. Used only as a fallback when nmap version detection
    # (`-sV`, which sets tunnel="ssl") is unavailable.
    IMPLICIT_TLS_PORTS = frozenset({
        443, 465, 563, 636, 853, 989, 990, 992, 993, 995, 5061, 6697,
    })
    IMPLICIT_TLS_SERVICES = frozenset({
        'https', 'smtps', 'imaps', 'pop3s', 'ftps', 'ftps-data', 'ldaps',
        'nntps', 'telnets', 'ircs', 'ircs-u', 'sips', 'https-alt', 'dnss',
    })

    @classmethod
    def _detect_tls_mode(cls, port) -> 'm.TlsMode':
        """Classify a port's TLS mode from an nmap ``<port>`` element.

        - ``implicit``: TLS is spoken directly (wrapped TLS). Detected either
          positively by nmap version detection (``tunnel="ssl"``, needs
          ``-sV``) or, when ``-sV`` is off, from a known implicit-TLS service
          name or port.
        - ``explicit``: a certificate was obtained (``ssl-cert`` script) on a
          port that is not a known wrapped-TLS one, i.e. TLS was negotiated via
          STARTTLS.
        - ``none``: no evidence of TLS.
        """
        service = port.find('service')
        service_name = service.attrs.get('name') if service is not None else None
        try:
            port_id = int(port.attrs.get('portid'))
        except (TypeError, ValueError):
            port_id = None

        if service is not None and service.attrs.get('tunnel') == 'ssl':
            return m.TlsMode.implicit
        if service_name in cls.IMPLICIT_TLS_SERVICES:
            return m.TlsMode.implicit
        if port.find('script', id = 'ssl-cert'):
            if port_id in cls.IMPLICIT_TLS_PORTS:
                return m.TlsMode.implicit
            return m.TlsMode.explicit
        return m.TlsMode.none

    @staticmethod
    def encode_target_for_filename(target: str):
        """Encode nmap target specification so it is safe to be used as part of filename.

        - Assumes input is a valid nmap target specification.
        - Tries to make encoded string reversible, but no guarantee.
        """
        s = target
        s = unicodedata.normalize('NFKD', s)
        s = target.strip()
        # replace wildcard with x
        s = s.replace('*', 'x')
        # replace CIDR / with --
        s = s.replace('/', '--')
        # trim very long target spec
        s = s[:100]
        return s

    @staticmethod
    def extract_ordered_hostnames(soup: bs4.PageElement) -> list[bs4.PageElement]:
        """List children <host> tag ordered by preferred type first

        Nmap can list multiple hostnames for a single host it scanned.
        - Hostname of `user` type is preferred for further processing because
          it is what original caller of nmap refer to the host as.
        - Next, hostname of `PTR` type is preferred because it's what discovered.
        - Lastly, if there is any other type of hostname, they all have equal
          priority.
        """
        hostnames_tags = soup.find_all('hostnames')
        assert len(hostnames_tags) == 1, 'There should only be one <hostnames> tag inside each <host> tag in nmap.xml'
        hostnames_tag = hostnames_tags[0]

        PRIORITY = {'user': 0, 'PTR': 1}
        def key(hostname):
            type_ = hostname.attrs.get('type')
            return PRIORITY.get(type_, 2)
        return sorted(
            hostnames_tag.find_all('hostname'),
            key = key,
        )

    @classmethod
    def extract_endpoints_from_xml(
        cls,
        source: bs4.PageElement | os.PathLike,
    ) -> list[m.Endpoint]:
        if not isinstance(source, bs4.PageElement):
            with open(source) as f:
                source = bs4.BeautifulSoup(f, 'xml')

        endpoints = []
        for host in source.find_all('host'):
            host_start = host.attrs.get('starttime', None)
            address = host.find('address').attrs.get('addr', None)
            hostnames = cls.extract_ordered_hostnames(host)
            preferred_hostname = (
                hostnames[0].attrs.get('name', None)
                if hostnames else
                None
            )
            open_ports = [
                port
                for port in host.find('ports').find_all('port')
                if port.find('state', state = 'open')
            ]
            for port in open_ports:
                tls_mode = cls._detect_tls_mode(port)

                # A port may have no <service> tag when nmap could not identify
                # the service; fall back to no application protocol / info.
                service_tag = port.find('service')
                if service_tag is not None:
                    application_protocol = service_tag.attrs.get('name', None)
                    service_infos = list(filter(None, [
                        service_tag.attrs.get('product', None),
                        service_tag.attrs.get('version', None),
                        (
                            (extra := service_tag.attrs.get('extrainfo', None))
                            and f'({extra})'
                        ),
                    ]))
                else:
                    application_protocol = None
                    service_infos = []

                endpoints.append(m.Endpoint(
                    ip = address,
                    hostname = preferred_hostname,
                    port = port.attrs.get('portid', None),
                    transport_protocol = port.attrs.get('protocol', 'tcp'),
                    application_protocol = application_protocol,
                    service_info = ' '.join(service_infos) or None,
                    first_seen = host_start,
                    # Port discovery is not a TLS/SSH scan: leave last_seen unset
                    # so a newly discovered endpoint is due for its first scan.
                    last_seen = None,
                    tls_mode = tls_mode,
                ))
        return endpoints

    @classmethod
    async def discover_endpoints(
        cls,
        target: str,
        *,
        base_output_dir: Path | None = None,
        xml_path_template: str = '{datestring}_{target}.nmap.xml',
        # `-sV` is required for reliable implicit-vs-explicit TLS detection:
        # nmap only emits tunnel="ssl" (positive wrapped-TLS evidence) under
        # version detection. It can be slow on services returning
        # unrecognizable data; pass detect_version=False to fall back to the
        # port/service-name heuristic in `_detect_tls_mode`.
        detect_version: bool = True,
        host_discovery: bool = False,
        ports: str | None = None,
    ):
        """From given nmap `target`, discover open ports, services.

        This will

        - Run nmap on the target and write XML output (to ``base_output_dir`` if
          given, otherwise a throwaway temp file).
        - Read back the XML output to extract items relevant to tlssec.
        - Return the completed process together with the discovered endpoints.

        Persisting the discovered endpoints is left to the caller (see the
        ``nmap`` CLI command), which prompts before adding them.
        """
        options = [
            # Get more updates while scanning, so
            # `run_subprocess(idle_timeout=...)` can be meaningfully used.
            '-vv',
            '--script=ssl-cert',
        ]
        if detect_version:
            options.append('-sV')
        if not host_discovery:
            options.append('-Pn')
        if ports:
            # TODO: Do we validate port string, or receive as structured list instead?
            options.append(f'-p{ports}')
        if base_output_dir:
            xml_path = base_output_dir / 'nmap' / xml_path_template.format(
                datestring = datetime.now().replace(microsecond = 0).isoformat(),
                target = cls.encode_target_for_filename(target),
            )
            if xml_path.exists():
                raise FileExistsError(f'Output path already exists at: {xml_path}')
            xml_path.parent.mkdir(parents = True, exist_ok = True)
            options += ('-oX', str(xml_path))
            completed_process = await run_subprocess('nmap', *options, target)
            endpoints = cls.extract_endpoints_from_xml(xml_path)
        else:
            # No persistent output requested, but nmap still has to write XML
            # for us to parse it back. Use a throwaway temp file cleaned up after.
            with tempfile.TemporaryDirectory() as tmpdir:
                xml_path = Path(tmpdir) / 'scan.nmap.xml'
                completed_process = await run_subprocess(
                    'nmap', *options, '-oX', str(xml_path), target,
                )
                endpoints = cls.extract_endpoints_from_xml(xml_path)

        return completed_process, endpoints
