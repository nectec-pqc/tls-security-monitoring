import logging
_logger = logging.getLogger(__name__)
from pathlib import Path
from textwrap import dedent

import click
import pandas as pd
import yaml

import tlssec.core.model as m
from tlssec.core.nmap import Nmap
from tlssec.core.testssl import Testssl


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
    # TODO: make tls_mode categorical
    df = pd.DataFrame(x.model_dump() for x in endpoints)
    df['display_hostname'] = df.hostname.map(lambda x: '-' if pd.isna(x) else f'`{x}`')
    df['display_app'] = df.apply((
        lambda row:
            f'ssl/{row.application_protocol}'
            if row.tls_mode == m.TlsMode.implicit else
            row.application_protocol
    ), axis = 1)
    df['display_service'] = df.apply((
        lambda row:
            '-'
            if pd.isna(row.service_info) else
            row.service_info
    ), axis = 1)

    df = df.set_index(['hostname', 'ip', 'port'])
    # TODO: use jinja templating engine?
    for hostname, by_hostname in df.groupby('hostname', dropna = False):
        print(
            f'table.cell(rowspan: {len(by_hostname.index)},'
            f' rotate(-90deg, reflow: true)[{by_hostname.display_hostname.iloc[0]}),'
        )
        for ip, by_ip in by_hostname.groupby('ip'):
            print(f'  table.cell(rowspan: {len(by_ip.index)}, [`{ip}`]),')
            for row in by_ip.reset_index().itertuples():
                action = (
                    'not scanned'
                    if row.tls_mode == m.TlsMode.none else
                    f'@{row.ip}_{row.port}'
                )
                print(f'    [{row.port}], [{row.display_app}], [{row.display_service}], [{action}],')

    print('---')

    template = dedent('''
        == Endpoint: {row.display_app} on `{row.ip}:{row.port}` <{row.ip}_{row.port}>

        #figure(
          table(
            columns: 2,
            [Domain Name], [{row.display_hostname}],
            [IP Address], [`{row.ip}`],
            [Port], [{row.port}],
            [Service], [{row.display_app}],
            [Version], [{row.display_service}],
          ),
        )

        เครื่องมือที่ใช้ (Tool Dependencies):

        - https://testssl.sh/

        === Post-Quantum Readiness

        #figure(
          table(
            columns: (1fr, 2fr),
            table.header[*Topic*][*Result*],
            [Quantum-safe key establishment],
            [
            ],

            [Quantum-safe cipher],
            [
            ],

            [Using quantum-safe signature algorithm in server certificate],
            [
            ],
          ),
        )

        /*
        === Supplementary Findings

        #for p in range(1, 7) [
          #image(
            "{row.ip}_{row.port}.html.pdf",
            page: p,
          )
        ]
        */
    ''')
    
    details_dir = Path('details')
    details_dir.mkdir(parents = True, exist_ok = True)
    # TODO: include SSH detail too
    with_detail = df[df.tls_mode != 'none']
    for row in with_detail.reset_index().itertuples():
        print(f'#include "details/{row.ip}_{row.port}.typ"')

        outpath = details_dir / f'{row.ip}_{row.port}.typ'
        with open(outpath, 'w') as f:
            f.write(template.format(row = row))

    return endpoints


@adhoc.command()
@click.option(
    '--force', '-f',
    is_flag = True,
    help = 'Overwrite existing output file',
)
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
def testssl_json_to_extracts_yaml(
    paths: list[Path],
    force: bool,
):
    """Produce typst document summarizing testssl result"""
    extracts = []
    for path in paths:
        _logger.info(f'processing {path}')
        extracts.extend(Testssl.extract_json(path))

    outpath = Path('testssl_extracts.yaml')
    if not force and outpath.exists():
        raise FileExistsError(f'file already exists {outpath}')
    with open(outpath, 'w') as f:
        yaml.safe_dump(extracts, f)
