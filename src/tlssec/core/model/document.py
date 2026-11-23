from contextlib import nullcontext
from importlib.metadata import version
from typing import (
    Any,
    Literal,
    Self,
)

from pydantic import BaseModel, Field
from pydantic_extra_types.semver import _VersionPydanticAnnotation as SemVer
import yaml

from tlssec.core.export.yaml import YamlDumper


class Document[D](BaseModel):
    """Document format originated from tlssec

    - Documents are self-describing.
      Takes inspiration from k8s API object:
      https://kubernetes.io/docs/concepts/overview/working-with-objects/#required-fields
    - Documents are serializable to file using YAML format.
    """
    tlssec_version: SemVer = Field(
        default = version('tlssec'),
        description = 'Version of tlssec software that created this document',
    )
    kind: str = Field(
        description = 'Subclass must set kind to a unique value to identify itself while serialized',
    )   
    # NOTE: k8s objects have [metadata](https://kubernetes.io/docs/reference/kubernetes-api/definitions/object-meta-v1-meta) field.
    # Should we have metadata field?
    # It could contain: creation datetime, annotation, ...
    data: D = Field(
        description = 'Main content of the document. Subclass should further specify structure of `data`.',
    )

    def dump(self, path: Path | None = None) -> str | None:
        """Serialize this document (and write to file if given a path)

        Every kind of `Document` can be dumped the same way using this method.
        However, loading serialized `Document` correctly depends on what
        filetypes are enabled for the session. Therefore, use
        `tlssec.app_state.filetype_registry.load` for loading instead.
        """
        stream_context = (
            nullcontext(None)
            if path is None
            else path.open('w')
        )
        with stream_context as stream:
            return yaml.dump(
                self.model_dump(mode = "json"),
                stream,
                Dumper = YamlDumper,
            )


class DocumentList[D](Document[list[Document[D]]]):
    """Document that is a list of other documents"""
    kind: Literal['list'] = 'list'
    data: list[Document[D]] = []
