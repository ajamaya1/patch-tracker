"""Core data model for the patch tracker.

The tracker normalizes two very differently shaped security feeds into a
common pair of records:

* :class:`Patch` -- a released remediation/update (an Apple security release
  such as "macOS Sequoia 15.5", or a Microsoft monthly rollup such as
  "June 2025 Security Updates").
* :class:`Cve` -- an individual vulnerability fixed by a patch.

Keeping the model deliberately small means both the SOFA (Apple) and MSRC
(Microsoft) sources can map onto it cleanly, and the CLI/report layers only
ever deal with these two dataclasses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# Tracking workflow states a user can assign to a patch.
TRACKING_STATUSES = (
    "new",          # freshly ingested, not yet triaged
    "in_progress",  # rollout/testing underway
    "applied",      # deployed everywhere it is needed
    "mitigated",    # not patched but risk reduced another way
    "wont_fix",     # accepted risk / not applicable
    "ignored",      # intentionally filtered out of reports
)
DEFAULT_STATUS = "new"

# Ordered severity ranking so we can compute the "worst" severity of a patch
# from its individual CVEs and sort/filter consistently across both sources.
SEVERITY_RANK = {
    "critical": 4,
    "important": 3,
    "high": 3,
    "moderate": 2,
    "medium": 2,
    "low": 1,
    "": 0,
    None: 0,
}


def severity_rank(severity: Optional[str]) -> int:
    """Return a sortable rank for a severity label (case-insensitive)."""
    if severity is None:
        return 0
    return SEVERITY_RANK.get(severity.strip().lower(), 0)


def worst_severity(severities) -> Optional[str]:
    """Pick the highest-ranked severity label from an iterable, or None."""
    best = None
    best_rank = 0
    for sev in severities:
        rank = severity_rank(sev)
        if rank > best_rank:
            best_rank = rank
            best = sev
    return best


@dataclass
class Cve:
    """A single vulnerability fixed by a :class:`Patch`."""

    cve_id: str
    patch_id: str
    source: str
    severity: Optional[str] = None
    impact: Optional[str] = None          # e.g. "Remote Code Execution"
    base_score: Optional[float] = None    # CVSS base score, when available
    exploited: bool = False               # known exploited in the wild
    publicly_disclosed: bool = False
    url: Optional[str] = None
    first_seen: Optional[str] = None      # date (YYYY-MM-DD) first ingested


@dataclass
class Patch:
    """A released update that remediates one or more CVEs."""

    source: str            # "apple" or "microsoft"
    patch_id: str          # stable, source-prefixed id (e.g. "msrc:2025-Jun")
    title: str
    product: Optional[str] = None
    version: Optional[str] = None
    release_date: Optional[str] = None     # ISO-8601 string
    url: Optional[str] = None
    severity: Optional[str] = None         # worst severity across its CVEs
    fetched_at: Optional[str] = None
    cves: List[Cve] = field(default_factory=list)

    @property
    def cve_count(self) -> int:
        return len(self.cves)

    @property
    def exploited_count(self) -> int:
        return sum(1 for c in self.cves if c.exploited)

    def recompute_severity(self) -> None:
        """Set ``severity`` to the worst severity among the patch's CVEs."""
        sev = worst_severity(c.severity for c in self.cves)
        if sev is not None:
            self.severity = sev
