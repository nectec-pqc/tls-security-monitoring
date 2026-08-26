import logging
_logger = logging.getLogger(__name__)
from pathlib import Path
from datetime import datetime

import click
import pandas as pd
import yaml

import tlssec.core.model as m
from tlssec.core.nmap import Nmap
from tlssec.core.testssl import Testssl
from tlssec.core.ssh_audit import SshAudit
from .colored_help import ColoredGroup, ColoredCommand
from .cli_state import CliState


@click.group(cls = ColoredGroup)
def adhoc():
    """Experimental features"""
    pass


@adhoc.command(cls = ColoredCommand)
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
@click.pass_context
def nmap_xmls_to_extracts_yaml(
    ctx,
    paths: list[Path],
    force: bool,
):
    """Produce yaml document summarizing nmap result"""
    state = ctx.find_object(CliState)
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

    outpath = state.settings.output_dir / 'nmap_extracts.yaml'
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


@adhoc.command(cls = ColoredCommand)
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
@click.pass_context
def testssl_json_to_extracts_yaml(
    ctx,
    paths: list[Path],
    force: bool,
):
    """Produce yaml document summarizing testssl result"""
    state = ctx.find_object(CliState)
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
            new_extracts[0]['raw_text'] = stdout_text
        else:
            _logger.warning(f'{stdout_path} does not exists, skipping.')

        extracts.extend(new_extracts)

    outpath = state.settings.output_dir / 'testssl_extracts.yaml'
    if not force and outpath.exists():
        raise FileExistsError(f'file already exists {outpath}')
    with open(outpath, 'w') as f:
        yaml.dump(extracts, f, Dumper=SetToListDumper)


@adhoc.command(cls = ColoredCommand)
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
@click.pass_context
def ssh_audit_json_to_extracts_yaml(
    ctx,
    paths: list[Path],
    force: bool,
):
    """Produce yaml document summarizing ssh-audit result"""
    state = ctx.find_object(CliState)
    extracts = []
    for path in paths:
        _logger.info(f'processing {path}')
        extracts.append(SshAudit.extract_json(path))

    outpath = state.settings.output_dir / 'ssh_audit_extracts.yaml'
    if not force and outpath.exists():
        raise FileExistsError(f'file already exists {outpath}')
    with open(outpath, 'w') as f:
        yaml.dump(extracts, f, Dumper=SetToListDumper)


# TODO: Allow taking selecting input from within database too
@adhoc.command(cls = ColoredCommand)
@click.option(
    '--out', '-o', 'report_path_pattern',
    default = '{now:%Y-%m-%d}-report',
    show_default = True,
    help = 'Pattern for naming report directory.',
)
@click.argument(
    'sources',
    type = click.Path(
        exists = True,
        dir_okay = False,
        path_type = Path,
    ),
    nargs = -1,
)
@click.pass_context
def export_report(
    ctx,
    sources,
    report_path_pattern,
):
    """Export results as a typst project

    Take data files from sub-scanners as arguments.
    They will be compiled into /data under report directory.

    This will overwrites files in --out directory.
    User is expected to use version control like git on the --out directory
    if there are some custom changes that needs to be kept.
    """
    import subprocess
    from tlssec.core.export.typst import TypstTemplates

    state = ctx.find_object(CliState)
    report_path = state.settings.output_dir / report_path_pattern.format(now = datetime.now())
    if report_path.is_file():
        _logger.error(
            'Can not create typst project.'
            f' Target already exists and is a file: {report_path}'
        )
        ctx.exit(1)
    _logger.info(f'populating report template at {report_path}')
    report_path.mkdir(parents = True, exist_ok = True)
    TypstTemplates.init('snapshot_report', report_path)

    compile_data_sources(sources, report_path / 'data')

    _logger.info('compiling report')
    completed_process = subprocess.run(
        ['typst', 'compile', 'main.typ'],
        cwd = report_path,
    )
    if completed_process != 0:
        _logger.error('typst failed to compile the exported report');


def compile_data_sources(sources: list[Path], outdir: Path):
    # TODO: combine extracts into single file? Do this after revising document format.
    from collections import defaultdict
    from tlssec.core.operation.file import external_document_loader
    extracts = defaultdict(list)
    for source in sources:
        _logger.info(f'extracting from {source}')
        filetype, content  = external_document_loader.run(source)
        match filetype:
            case 'testssl-pretty':
                pass
            case 'ssh-audit':
                extracts['ssh-audit'].append(
                    SshAudit.extract_json(content)
                )
            case 'nmap':
                pass
    outdir.mkdir(parents = True, exist_ok = True)

    outpath = outdir / 'ssh_audit_extracts.yaml'
    with open(outpath, 'w') as f:
        yaml.dump(extracts['ssh-audit'], f, Dumper = SetToListDumper)
    
    # TODO: complete extraction of other types

    return extracts
