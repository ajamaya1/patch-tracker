"""Plain-text table and summary rendering for the CLI."""

from __future__ import annotations

from typing import List, Sequence


def render_table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    """Render an aligned, monospace-friendly text table.

    Empty row sets render as a single "(no results)" line so callers don't
    each have to special-case it.
    """
    if not rows:
        return "(no results)"
    cols = [str(h) for h in headers]
    str_rows: List[List[str]] = [
        ["" if c is None else str(c) for c in row] for row in rows
    ]
    widths = [len(c) for c in cols]
    for row in str_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt(cells: Sequence[str]) -> str:
        return "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

    sep = "  ".join("-" * w for w in widths)
    lines = [fmt(cols), sep]
    lines.extend(fmt(r) for r in str_rows)
    return "\n".join(lines)


def short_date(value) -> str:
    """Trim an ISO timestamp down to its date portion for display."""
    if not value:
        return ""
    return str(value)[:10]
