from pathlib import Path
from typing import (
    Annotated,
    Any,
)

import bs4
from pydantic import Field
import yaml

import tlssec.core.model as m
from tlssec.core.nmap import NmapRaw
from tlssec.core.ssh_audit import SshAudit
from tlssec.core.testssl import Testssl
from tlssec.task import as_task, FirstSuccessTaskGroup


@as_task()
def ReadText(source: Path | str) -> str:
    match source:
        case Path():
            return source.read_text()
        case str():
            return source
        case _:
            raise TypeError('source of text must either be a file path to read from, or string content to be used directly')


@as_task(dependency = ReadText)
def ReadYaml(content: str) -> Any:
    try:
        return yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise ValueError('Content is not a valid YAML') from e


@as_task(dependency = ReadText)
def ReadXml(content: str) -> m.XmlRaw:
    return m.XmlRaw(
        type = 'xml',
        content = content,
    )


@as_task(dependency = ReadYaml)
def ReadTlssecNativeDocument(doc) -> m.Document:
    ConcreteExternalRaw = Annotated[
        # TODO: Add more concrete raw types here
        NmapRaw,
        Field(discriminator = 'type'),
    ]
    # There are native docs that are not just wrapper of external document
    # TODO: Add more native document types here
    NativeDocument = m.ExternalDocument[ConcreteExternalRaw]
    return NativeDocument.model_validate(doc)


@as_task(dependency = ReadXml)
def ReadNmapXml(doc: m.XmlRaw) -> m.ExternalDocument[NmapRaw]:
    return m.ExternalDocument[NmapRaw](
        data = NmapRaw(
            content = doc.content,
            soup = doc.soup,
        ),
    )


@as_task(dependency = ReadYaml)
def ReadTestsslJsonPretty(doc) -> m.ExternalDocument:
    return Testssl.try_parse(doc)


@as_task(dependency = ReadYaml)
def ReadSshAudit(doc) -> m.ExternalDocument:
    return SshAudit.try_parse(doc)


class FiletypeRegistry:
    """Keep tabs of what file loaders are enabled"""
    def __init__(self):
        # NOTE: Later, we might want to register FiletypeSpec object
        # containing name, loader, source (extension enabling the filetype)
        # instead of just the loader tasks.
        # TODO: discover tlssec extensions and register filetypes they enabled
        self._loader = FirstSuccessTaskGroup(
            [
                ReadTlssecNativeDocument,
                ReadTestsslJsonPretty,
                ReadSshAudit,
                ReadNmapXml,
            ],
            skippable = ValueError,
        )

    def load(self, path: Path | str) -> m.Document:
        return self._loader.run(path)
