import asyncio
from pathlib import Path
from datetime import datetime
import re
import unicodedata

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

    # TODO: add port options
    @classmethod
    async def discover_endpoints(
        cls,
        target: str,
        *,
        base_output_dir: Path | None = None,
        xml_path_template: str = '{datestring}_{target}.nmap.xml',
        # NOTE: `-sV` take a long time on service responding with unrecognizable data.
        # TODO: Find a different way to speed up in that case.
        detect_version: bool = True,
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
        if ports:
            # TODO: Do we validate port list, or receive as list instead?
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

        result = await run_subprocess(
            'nmap', *options, target,
        )
        return result
        #raise NotImplementedError('The rest of function has not been implemented yet')
        # TODO: record Scan object into database
        # TODO: Parse XML output
        # TODO: record discovered Endpoint object into database
