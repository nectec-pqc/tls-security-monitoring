import asyncio
from pathlib import Path
from datetime import datetime
import re
import unicodedata

from bs4 import BeautifulSoup

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
    def extract_ordered_hostnames(soup: BeautifulSoup) -> list[BeautifulSoup]:
        """List children <host> tag ordered by preferred type first

        Nmap can list multiple hostnames for a single host it scanned.
        - Hostname of `user` type is preferred for further processing because
          it is what original caller of nmap refer to the host as.
        - Next, hostname of `PTR` type is preferred because it's what discovered.
        - Lastly, if there is any other type of hostname, they all have equal
          priority.
        """
        def key(hostname):
            type_ = hostname.attrs.get('type', None),
            return (
                type_ is not None,
                type_ or '',
            )
        return sorted(
            soup.find('hostnames').find_all('hostname'),
            key = key,
        )

    @classmethod
    def extract_endpoints_from_xml_soup(
        cls,
        soup: BeautifulSoup,
    ) -> list[m.Endpoint]:
        endpoints = []
        for host in soup.find_all('host'):
            address = host.find('address').attrs.get('addr', None)
            hostnames = cls.extract_ordered_hostnames(host)
            preferred_hostname = hostnames and hostnames[0].attrs.get('name', None)
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

                endpoints.append(m.Endpoint(
                    ip = address,
                    hostname = preferred_hostname,
                    port = port.attrs.get('portid', None),
                    transport_protocol = port.attrs.get('protocol', 'tcp'),
                    application_protocol = port.find('service').attrs.get('name', None),
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

        - Run nmap on the target and store XML output.
        - Read back XML output file to extract items relevant to tlssec.
        - Store Scan object in database.
        - Store found endpoints in database.
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

        completed_process = await run_subprocess(
            'nmap', *options, target,
        )

        with open(xml_path) as f:
            soup = BeautifulSoup(f, 'xml')

        endpoints = cls.extract_endpoints_from_xml_soup(soup)

        return completed_process, endpoints
        #raise NotImplementedError('The rest of function has not been implemented yet')
        # TODO: record Scan object into database
        # TODO: record discovered Endpoint object into database
