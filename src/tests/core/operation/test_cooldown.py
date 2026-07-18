from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pandas as pd

from tlssec.core.operation import is_in_cooldown


COOLDOWN = pd.Timedelta('7 days')


def _ep(last_seen):
    return SimpleNamespace(last_seen=last_seen)


def test_never_scanned_is_due():
    # last_seen is None -> the endpoint has never been scanned, always due.
    assert not is_in_cooldown(_ep(None), COOLDOWN, datetime.now())


def test_recently_scanned_is_in_cooldown():
    now = datetime(2026, 7, 17, 12, 0, 0)
    assert is_in_cooldown(_ep(now - timedelta(days=1)), COOLDOWN, now)


def test_scanned_before_cooldown_is_due():
    now = datetime(2026, 7, 17, 12, 0, 0)
    assert not is_in_cooldown(_ep(now - timedelta(days=8)), COOLDOWN, now)


def test_boundary_exactly_at_cooldown_is_due():
    now = datetime(2026, 7, 17, 12, 0, 0)
    # last == now - cooldown, comparison is strict (last > cutoff), so due.
    assert not is_in_cooldown(_ep(now - COOLDOWN.to_pytimedelta()), COOLDOWN, now)


def test_tz_aware_last_seen_vs_naive_now_does_not_raise():
    # last_seen from Postgres is tz-aware; the run's `now` is naive. Mixed
    # awareness must be normalized rather than raise TypeError.
    now = datetime(2026, 7, 17, 12, 0, 0)
    ep = _ep(datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc))
    assert is_in_cooldown(ep, COOLDOWN, now)
