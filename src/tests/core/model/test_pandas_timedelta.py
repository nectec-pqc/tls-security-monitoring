from contextlib import nullcontext

import pytest
import pandas as pd
from pydantic import (
    TypeAdapter,
    ValidationError,
)

from tlssec.core.model.validator import PandasTimedelta


@pytest.mark.parametrize(
    'value, unit, expectation',
    [
        pytest.param(
            '1h',
            'days',
            nullcontext(pd.Timedelta(1, 'h')),
            id = 'Unit is ignored if input is string',
        ),
        pytest.param(
            13,
            'minutes',
            nullcontext(pd.Timedelta(13, 'm')),
            id = 'Unit is used when input is number',
        ),
        pytest.param(
            1.3,
            None,
            nullcontext(pd.Timedelta(1.3, 's')),
            id = 'Default unit is seconds',
        ),
        pytest.param(
            '3 minutes 29 seconds',
            None,
            nullcontext(pd.Timedelta(209, 's')),
            id = 'Multi-part description',
        ),
        pytest.param(
            pd.Timedelta('1D'),
            None,
            nullcontext(pd.Timedelta('1D')),
            id = 'Accepts already parsed timedelta',
        ),
        pytest.param(
            None,
            None,
            pytest.raises(ValidationError),
            id = 'Wrong input type',
        ),
        pytest.param(
            'not a timedelta',
            None,
            pytest.raises(ValidationError, match = 'not a timedelta'),
        ),
    ],
)
def test_validate_pandas_timedelta(value, unit, expectation):
    type_ = TypeAdapter(PandasTimedelta(unit))
    with expectation as expected:
        result = type_.validate_python(value)
        if expected is not None:
            assert result == expected


@pytest.mark.parametrize(
    'value, unit',
    [
        (2.34, 'seconds'),
        ('1h 2m 3s 4ms', None),
        (2.34, 'ns'),
        (2.34, None),
    ],
)
def test_roundtrip_pandas_timedelta(value, unit):
    type_ = TypeAdapter(PandasTimedelta(unit))
    parsed = type_.validate_python(value)
    serialized = type_.dump_python(parsed, mode = 'json')
    re_parsed = type_.validate_python(serialized)
    assert parsed == re_parsed
