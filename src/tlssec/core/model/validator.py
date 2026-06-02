from typing import Annotated

from pydantic import (
    BeforeValidator,
)


EmptyToNoneStr = Annotated[
    str | None,
    BeforeValidator(lambda v: None if v == '' else v),
]
