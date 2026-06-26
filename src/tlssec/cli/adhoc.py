import logging
_logger = logging.getLogger(__name__)
from pathlib import Path

import click
import pandas as pd

import tlssec.core.model as m
from tlssec.core.nmap import Nmap


@click.group()
def adhoc():
    """Experimental features"""
    pass


@adhoc.command()
@click.argument(
    'paths',
    metavar = 'files',
    type = click.Path(
        exists = True,
        dir_okay = False,
        path_type = Path,
    ),
    nargs = -1,
)
def nmap_xmls_to_typst(
    paths: list[Path],
):
    """Produce typst document summarizing nmap result"""
    endpoints = []
    for path in paths:
        _logger.info(f'processing {path}')
        # TODO: handle error separately for each file
        endpoints.extend(
            Nmap.extract_endpoints_from_xml(path)
        )
    df = pd.DataFrame(x.model_dump() for x in endpoints)
    df = df.set_index(['hostname', 'ip', 'port'])
    # TODO: use jinja templating engine?
    for hostname, by_hostname in df.groupby('hostname', dropna = False):
        display_hostname = '-' if pd.isna(hostname) else f'`{hostname}`'
        print(f'table.cell(rowspan: {len(by_hostname.index)}, rotate(-90deg, reflow: true)[{display_hostname}]),')
        for ip, by_ip in by_hostname.groupby('ip'):
            print(f'  table.cell(rowspan: {len(by_ip.index)}, [`{ip}`]),')
            for row in by_ip.reset_index().itertuples():
                action = (
                    'not scanned'
                    if row.tls_mode == m.TlsMode.none else
                    f'@{row.ip}_{row.port}'
                )
                display_app = (
                    f'ssl/{row.application_protocol}'
                    if row.tls_mode == m.TlsMode.implicit else
                    row.application_protocol
                )
                display_service = (
                    '-'
                    if pd.isna(row.service_info) else
                    row.service_info
                )
                print(f'    [{row.port}], [{display_app}], [{display_service}], [{action}],')
    return endpoints
