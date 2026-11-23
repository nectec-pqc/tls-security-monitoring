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

    def to_file(self, path: Path):
        """Write this document to file at the given path."""
        with path.open('w') as f:
            yaml.dump(
                self.model_dump(mode = "json"),
                f,
                Dumper = YamlDumper,
            )

    @classmethod
    def from_file(cls, path: Path) -> Self:
        """Load document from file at the given path."""
        with path.open('r') as f:
            content = yaml.safe_load(f)
        return cls.model_validate(base_content)


class DocumentList[D](Document[list[Document[D]]]):
    """Document that is a list of other documents"""
    kind: Literal['list'] = 'list'
    data: list[Document[D]] = []
