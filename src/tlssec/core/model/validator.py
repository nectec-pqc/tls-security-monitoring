from typing import Annotated

from pydantic import (
    BeforeValidator, 
    AfterValidator,
)


EmptyToNoneStr = Annotated[
    str | None,
    BeforeValidator(lambda v: None if v == '' else v),
]

def _validate_url_path(v: str) -> str:
    if not v.startswith('/'):
        raise ValueError("path must start with '/'")
    if '?' in v or '#' in v:
        raise ValueError('path must not contain query string or fragment')
    return v


UrlPath = Annotated[str, AfterValidator(_validate_url_path)]
