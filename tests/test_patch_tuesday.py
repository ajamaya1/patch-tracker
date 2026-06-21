import datetime as dt

from patch_tracker import patch_tuesday as pt


def test_second_tuesday_known_months():
    # June 2025 Patch Tuesday is the 10th; May 2025 is the 13th.
    assert pt.second_tuesday(2025, 6) == dt.date(2025, 6, 10)
    assert pt.second_tuesday(2025, 5) == dt.date(2025, 5, 13)
    # January 2026 Patch Tuesday is the 13th.
    assert pt.second_tuesday(2026, 1) == dt.date(2026, 1, 13)


def test_second_tuesday_is_always_a_tuesday():
    for year in (2024, 2025, 2026):
        for month in range(1, 13):
            assert pt.second_tuesday(year, month).weekday() == 1  # Tuesday
            assert 8 <= pt.second_tuesday(year, month).day <= 14


def test_latest_patch_tuesday():
    # On Patch Tuesday itself, that day is the latest.
    assert pt.latest_patch_tuesday(dt.date(2025, 6, 10)) == dt.date(2025, 6, 10)
    # Day before -> previous month's Patch Tuesday.
    assert pt.latest_patch_tuesday(dt.date(2025, 6, 9)) == dt.date(2025, 5, 13)
    # January rolls back to December of the prior year.
    assert pt.latest_patch_tuesday(dt.date(2026, 1, 1)) == dt.date(2025, 12, 9)


def test_patch_tuesday_for_update_id():
    assert pt.patch_tuesday_for_update_id("2025-Jun") == dt.date(2025, 6, 10)
    assert pt.patch_tuesday_for_update_id("2025-May") == dt.date(2025, 5, 13)
    assert pt.patch_tuesday_for_update_id("garbage") is None
    assert pt.patch_tuesday_for_update_id("") is None
