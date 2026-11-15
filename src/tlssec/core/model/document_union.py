from typing import (
    Annotated,
    Union,
)

from pydantic import Field

from .document import Document
from .external_document import ExternalDocument


AnyDocument = Annotated[
    Union[
        # TODO: Add more concrete document types
        ExternalDocument,
    ],
    Field(discriminator = 'kind'),
]
