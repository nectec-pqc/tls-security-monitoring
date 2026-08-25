from pathlib import Path
from typing import Any

import bs4
import yaml

from tlssec.core.nmap import Nmap
from tlssec.core.ssh_audit import SshAudit
from tlssec.core.testssl import Testssl
from tlssec.task import as_task, FirstSuccessTaskGroup


@as_task()
def ReadTextFile(path: Path) -> str:
    return path.read_text()


@as_task(dependency = ReadTextFile)
def ReadYaml(content: str) -> Any:
    try:
        return yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise ValueError('Content is not a valid YAML') from e


@as_task(dependency = ReadTextFile)
def ReadXml(content: str) -> bs4.PageElement:
    try:
        return bs4.BeautifulSoup(content, 'xml')
    except Exception as e:
        raise ValueError('Can not read content as XML') from e


# TODO: Have special classes to represent each kind of document.


@as_task(dependency = ReadXml)
def ReadNmapXml(doc):
    return 'nmap', Nmap.try_parse(doc)


@as_task(dependency = ReadYaml)
def ReadTestsslJsonPretty(doc):
    return 'testssl-pretty', Testssl.try_parse(doc)


@as_task(dependency = ReadYaml)
def ReadSshAudit(doc):
    return 'ssh-audit', SshAudit.try_parse(doc)


external_document_loader = FirstSuccessTaskGroup(
    [
        ReadTestsslJsonPretty,
        ReadSshAudit,
        ReadNmapXml,
    ],
    skippable = ValueError,
)
