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
            host_end = host.attrs.get('endtime', None)
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
                if port.find('service', tunnel = 'ssl'):
                    tls_mode = m.TlsMode.implicit
                elif port.find('script', id = 'ssl-cert'):
                    tls_mode = m.TlsMode.explicit
                else:
                    tls_mode = m.TlsMode.none

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
                    last_seen = host_end,
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
        # NOTE: `-sV` take a long time on service responding with unrecognizable data.
        # TODO: Find a different way to speed up in that case.
        detect_version: bool = False,
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
