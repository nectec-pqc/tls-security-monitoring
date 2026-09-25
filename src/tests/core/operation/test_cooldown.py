from contextlib import nullcontext
from datetime import datetime, timedelta, UTC
from types import SimpleNamespace

import pandas as pd
import pytest

from tlssec.core.operation import is_in_cooldown


def mock_endpoint(last_seen):
    return SimpleNamespace(last_seen = last_seen)


@pytest.mark.parametrize(
    'kwargs, expectation',
    [
        pytest.param(
            {
                'endpoint': mock_endpoint(None),
                'cooldown': pd.Timedelta('7 days'),
                'now': datetime.now(UTC),
            },
            nullcontext(False),
            id = 'endpoint that has never been scanned is never in cooldown'
        ),
        pytest.param(
            {
                'endpoint': mock_endpoint(last_seen := pd.Timestamp('2026-07-16')),
                'cooldown': pd.Timedelta('7 days'),
                'now': last_seen + pd.Timedelta('1 days'),
            },
            nullcontext(True),
            id = 'naive time, in cooldown'
        ),
        pytest.param(
            {
                'endpoint': mock_endpoint(last_seen := pd.Timestamp('2026-07-16')),
                'cooldown': pd.Timedelta('7 days'),
                'now': last_seen + pd.Timedelta('8 days'),
            },
            nullcontext(False),
            id = 'naive time, out of cooldown'
        ),
        pytest.param(
            {
                'endpoint': mock_endpoint(last_seen := pd.Timestamp('2026-07-16')),
                'cooldown': (cooldown := pd.Timedelta('7 days')),
                'now': last_seen + cooldown,
            },
            nullcontext(False),
            id = 'naive time, exactly at cooldown boundary is considered out of cooldown'
        ),
        pytest.param(
            {
                'endpoint': mock_endpoint(pd.Timestamp('2026-07-16')),
                'cooldown': pd.Timedelta('7 days'),
                'now': pd.Timestamp('2026-07-17', tz = UTC),
            },
            pytest.raises(TypeError),
            id = 'Mixed tz awareness is not allowed'
        ),
        pytest.param(
            {
                'endpoint': mock_endpoint(pd.Timestamp('2026-07-16T12:00', tz = '+07:00')),
                'cooldown': pd.Timedelta('2 hours'),
                'now': pd.Timestamp('2026-07-16T15:00', tz = '+09:00'),
            },
            nullcontext(True),
            id = 'In cooldown only if both timezone are not ignored'
        ),
        pytest.param(
            {
                'endpoint': mock_endpoint(pd.Timestamp('2026-07-16T12:00', tz = '+07:00')),
                'cooldown': pd.Timedelta('2 hours'),
                'now': pd.Timestamp('2026-07-16T13:00', tz = '+05:00'),
            },
            nullcontext(False),
            id = 'Out of cooldown only if both timezone are not ignored'
        ),
    ],
)
def test_is_in_cooldown(kwargs, expectation):
    with expectation as expected:
        result = is_in_cooldown(**kwargs)
        if isinstance(expected, bool):
            assert result == expected
