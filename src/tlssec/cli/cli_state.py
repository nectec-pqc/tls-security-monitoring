from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
)
from sqlmodel import Session


class CliState(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed = True)

    session: Session | None = None

    # TODO: If settings can be changed via --config-file option on CLI,
    # then the effective settings should be stored in CliState.
    # Also, other operations will have to be injected with settings dependency.
