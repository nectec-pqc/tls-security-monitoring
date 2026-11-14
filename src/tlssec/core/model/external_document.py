from abc import ABC
from typing import (
    Annotated,
    Any,
    Literal,
    Self,
)

from pydantic import (
    Base64Bytes,
    BaseModel,
    Field,
    JsonValue,
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


class TextRaw(BaseExternalRaw):
    """Used when raw data is text, but with structure that is incompatible with JSON."""
    representation: Literal['text'] = 'text'
    content: str


class BinaryRaw(BaseExternalRaw):
    """Used as a last resort to represent raw data as base64-encoded string."""
    representation: Literal['binary'] = 'binary'
    content: Base64Bytes


ExternalRaw = Annotated[
    StructuredRaw | TextRaw | BinaryRaw,
    Field(discriminator = 'representation'),
]


class ExternalDocument(Document):
    """Document that is actually just a wrapper around external data format."""
    kind: Literal['external'] = 'external'
    data: ExternalRaw
