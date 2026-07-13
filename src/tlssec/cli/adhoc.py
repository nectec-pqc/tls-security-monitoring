import logging
_logger = logging.getLogger(__name__)
from pathlib import Path
from collections import defaultdict

import click
import pandas as pd
import yaml

import tlssec.core.model as m
from tlssec.core.nmap import Nmap
from tlssec.core.testssl import Testssl
from tlssec.core.ssh_audit import SshAudit


@click.group()
def adhoc():
    """Experimental features"""
    pass


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
def nmap_xmls_to_extracts_yaml(
    paths: list[Path],
    force: bool,
):
    """Produce yaml document summarizing nmap result"""
    endpoints = []
    for path in paths:
        _logger.info(f'processing {path}')
        # TODO: handle error separately for each file
        endpoints.extend(
            Nmap.extract_endpoints_from_xml(path)
        )

    endpoints.sort(key = lambda x: (
        not x.hostname,
        x.hostname,
        not x.ip,
        x.ip,
        not x.port,
        x.port,
    ))

    extracts = [
        endpoint.model_dump(mode = 'json', exclude = ['id', 'part_of_service_id'])
        for endpoint in endpoints
    ]

    outpath = Path('nmap_extracts.yaml')
    if not force and outpath.exists():
        raise FileExistsError(f'file already exists {outpath}')
    with open(outpath, 'w') as f:
        yaml.dump(extracts, f)
    
    return endpoints


# TODO: move to another file?
class SetToListDumper(yaml.SafeDumper):
    pass

SetToListDumper.add_representer(
    set,
    (
        lambda dumper, data:
            dumper.represent_list(sorted(data))
    ),
)


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
    """Produce yaml document summarizing testssl result"""
    extracts = []
    for path in paths:
        _logger.info(f'processing {path}')
        new_extracts = Testssl.extract_json(path)
        if not new_extracts:
            continue

        stdout_path = path.with_suffix('.stdout')
        if stdout_path.exists():
            stdout_text = stdout_path.read_text()
            if len(new_extracts) > 1:
                _logger.warning(
                    f'{stdout_path} likely contain raw result for multiple endpoints.'
                    ' only the first endpoint will be populated with raw to avoid repeating the same data.'
                )
            new_extracts[0]['raw'] = stdout_text
        else:
            _logger.warning(f'{stdout_path} does not exists, skipping.')

        extracts.extend(new_extracts)

    outpath = Path('testssl_extracts.yaml')
    if not force and outpath.exists():
        raise FileExistsError(f'file already exists {outpath}')
    with open(outpath, 'w') as f:
        yaml.dump(extracts, f, Dumper=SetToListDumper)


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
def ssh_audit_json_to_extracts_yaml(
    paths: list[Path],
    force: bool,
):
    """Produce yaml document summarizing ssh-audit result"""
    extracts = []
    for path in paths:
        _logger.info(f'processing {path}')
        extracts.append(SshAudit.extract_json(path))

    outpath = Path('ssh_audit_extracts.yaml')
    if not force and outpath.exists():
        raise FileExistsError(f'file already exists {outpath}')
    with open(outpath, 'w') as f:
        yaml.dump(extracts, f, Dumper=SetToListDumper)
