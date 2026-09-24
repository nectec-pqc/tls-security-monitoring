from datetime import datetime, timedelta, UTC
from types import SimpleNamespace

import pandas as pd
import pytest

from tlssec.core.operation import is_in_cooldown


def mock_endpoint(last_seen):
    return SimpleNamespace(last_seen = last_seen)


@pytest.mark.parametrize(
    'kwargs, expected',
    [
        pytest.param(
            {
                'endpoint': mock_endpoint(None),
                'cooldown': pd.Timedelta('7 days'),
                'now': datetime.now(UTC),
            },
            False,
            id = 'endpoint that has never been scanned is never in cooldown'
        ),
        pytest.param(
            {
                'endpoint': mock_endpoint(last_seen := pd.Timestamp('2026-07-16')),
                'cooldown': pd.Timedelta('7 days'),
                'now': last_seen + pd.Timedelta('1 days'),
            },
            True,
            id = 'naive time, in cooldown'
        ),
        pytest.param(
            {
                'endpoint': mock_endpoint(last_seen := pd.Timestamp('2026-07-16')),
                'cooldown': pd.Timedelta('7 days'),
                'now': last_seen + pd.Timedelta('8 days'),
            },
            False,
            id = 'naive time, out of cooldown'
        ),
        pytest.param(
            {
                'endpoint': mock_endpoint(last_seen := pd.Timestamp('2026-07-16')),
                'cooldown': (cooldown := pd.Timedelta('7 days')),
                'now': last_seen + cooldown,
            },
            False,
            id = 'naive time, exactly at cooldown boundary is considered out of cooldown'
        ),
        # TODO: Need to check tz awareness more rigurously
        pytest.param(
            {
                'endpoint': mock_endpoint(pd.Timestamp('2026-07-16')),
                'cooldown': pd.Timedelta('7 days'),
                'now': pd.Timestamp('2026-07-17', tz = UTC),
            },
            True,
            id = 'only check that mixed tz awareness does not raise exception'
        ),
    ],
)
def test_is_in_cooldown(kwargs, expected):
    result = is_in_cooldown(**kwargs)
    assert result == expected
