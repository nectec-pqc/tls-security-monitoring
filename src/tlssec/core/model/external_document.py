from abc import ABC
from collections.abc import Mapping
from typing import (
    Annotated,
    Any,
    Literal,
    Self,
)

import bs4
from pydantic import (
    Base64Bytes,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    model_validator,
)

from .document import Document


class BaseExternalRaw(BaseModel, ABC):
    """Raw data of an external format.

    - The data maybe classified as either structured, unstructured text, or binary.
    - Subclass may add private attributes to annotate the raw data, or cache processed data.
    """
    type: str = Field(
        description = 'Type of external document. Subclass must set to a unique value.',
    )
    representation: str = Field(
        description = 'How content is represented or encoded in content field',
    )
    content: Any


class StructuredRaw(BaseExternalRaw):
    """Used when raw data is already structured (e.g., JSON, YAML, or TOML)."""
    representation: Literal['structured'] = 'structured'
    content: JsonValue


class XmlRaw(BaseExternalRaw):
    """Used when raw data is XML."""
    model_config = ConfigDict(arbitrary_types_allowed = True)

    representation: Literal['xml'] = 'xml'
    content: str
    soup: bs4.Tag = Field(
        default = None,
        exclude = True,
        description = (
            'Cached bs4-parsed version of `content` field.'
            ' During creation, if only one of `content` or `bs4` is missing it will be derived from the other.'
            ' Pass `bs4` in directly to avoid re-parsing.'
            ' Pass `content` in if preserving XML string formatting is important.'
            ' (`bs4` parsing not preserve XML string formatting.)'
        ),
    )

    @model_validator(mode = 'wrap')
    @classmethod
    def accept_content_as_bs4_tag(cls, data: Any, handler) -> Self:
        soup = None
        if isinstance(data, Mapping):
            if isinstance(data.get('soup'), bs4.Tag):
                soup = data['soup']
                if data.get('content') is None:
                    data = {**data, 'content': str(soup)}
        self = handler(data)
        if soup is None:
            try:
                soup = bs4.BeautifulSoup(self.content, 'xml')
            except Exception as e:
                raise ValueError('Can not read content as XML') from e
        self.soup = soup
        return self


class TextRaw(BaseExternalRaw):
    """Used when raw data is text, but with structure that is incompatible with JSON."""
    representation: Literal['text'] = 'text'
    content: str


class BinaryRaw(BaseExternalRaw):
    """Used as a last resort to represent raw data as base64-encoded string."""
    representation: Literal['binary'] = 'binary'
    content: Base64Bytes


ExternalRaw = Annotated[
    StructuredRaw | XmlRaw | TextRaw | BinaryRaw,
    Field(discriminator = 'representation'),
]


class ExternalDocument(Document):
    """Document that is actually just a wrapper around external data format."""
    kind: Literal['external'] = 'external'
    data: ExternalRaw
