"""Patch Tuesday helpers for Microsoft (MSRC) updates.

Microsoft ships its monthly security updates on "Patch Tuesday" -- the second
Tuesday of each month. MSRC update ids are month-stamped (e.g. ``2025-Jun``),
so we can map an id to the exact Patch Tuesday date and label/sort the
Microsoft side of the dashboard around it.
"""

from __future__ import annotations

import calendar
import datetime as _dt
from typing import Optional

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


def second_tuesday(year: int, month: int) -> _dt.date:
    """Return the date of Patch Tuesday (2nd Tuesday) for a given month."""
    # calendar.weekday: Monday=0 .. Sunday=6; Tuesday=1.
    first_weekday, _ = calendar.monthrange(year, month)
    # Days until the first Tuesday (>= 1st of month).
    offset = (1 - first_weekday) % 7
    first_tuesday = 1 + offset
    return _dt.date(year, month, first_tuesday + 7)


def latest_patch_tuesday(today: Optional[_dt.date] = None) -> _dt.date:
    """Return the most recent Patch Tuesday on or before ``today``."""
    today = today or _dt.date.today()
    this_month = second_tuesday(today.year, today.month)
    if today >= this_month:
        return this_month
    # Fall back to the previous month's Patch Tuesday.
    year = today.year - 1 if today.month == 1 else today.year
    month = 12 if today.month == 1 else today.month - 1
    return second_tuesday(year, month)


def patch_tuesday_for_update_id(update_id: str) -> Optional[_dt.date]:
    """Map an MSRC update id like ``2025-Jun`` to its Patch Tuesday date.

    Returns ``None`` if the id cannot be parsed.
    """
    if not update_id or "-" not in update_id:
        return None
    year_str, _, month_str = update_id.partition("-")
    try:
        year = int(year_str)
    except ValueError:
        return None
    month = _MONTHS.get(month_str.strip().lower()[:3])
    if not month:
        return None
    return second_tuesday(year, month)
