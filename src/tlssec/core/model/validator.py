from typing import Annotated
from functools import cache

from pydantic import (
    BeforeValidator, 
    AfterValidator,
    PlainValidator,
    PlainSerializer,
    WithJsonSchema,
)
from pydantic_core import core_schema
import pandas as pd


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


@cache
def PandasTimedelta(unit: str | None = None):
    """Produce pd.Timedelta subclass with added pydantic validation

    Unlike pydantic built-in parsing of timedelta,
    pd.Timedelta supports more intuitive parsing of timedelta from string.

    unit:
        If input is a number, interpret using this unit.
        Ignored if input is not a number.
        Default to seconds.
    """
    if unit is None:
        unit = 'seconds'

    def validate_pandas_timedelta(v) -> pd.Timedelta:
        if isinstance(v, int | float):
            return pd.to_timedelta(v, unit)
        if v is None:
            raise ValueError('None is not a timedelta')
        return pd.to_timedelta(v)

    def serialize_pandas_timedelta(v: pd.Timedelta) -> str:
        return str(v)

    return Annotated[
        pd.Timedelta,
        PlainValidator(validate_pandas_timedelta),
        PlainSerializer(serialize_pandas_timedelta, when_used = 'json'),
        WithJsonSchema({
            'type': 'string',
            'format': 'duration',
        }),
    ]
