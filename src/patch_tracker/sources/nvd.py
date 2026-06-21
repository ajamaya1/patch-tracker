"""Third-party vendor advisories from the NVD CVE API 2.0.

The NIST National Vulnerability Database (https://nvd.nist.gov) exposes a free
JSON API that returns CVEs with CVSS scores. Where CISA KEV only lists the
*exploited* subset, NVD gives the broader set of recent high/critical CVEs per
vendor -- so we use it to populate third-party software sections (Adobe, Cisco,
Fortinet, Citrix, Ivanti, VMware, Atlassian, Zoom, …) with severity and score.

API: ``GET https://services.nvd.nist.gov/rest/json/cves/2.0`` with
``keywordSearch=<vendor>`` and a ``pubStartDate``/``pubEndDate`` window.

Response (trimmed)::

    {"vulnerabilities": [
      {"cve": {
        "id": "CVE-2025-1234",
        "published": "2025-06-03T10:15:00.000",
        "descriptions": [{"lang": "en", "value": "Acrobat Reader use-after-free…"}],
        "metrics": {"cvssMetricV31": [{"cvssData":
          {"baseScore": 8.8, "baseSeverity": "HIGH"}}]}
      }}
    ]}

Each vendor is grouped into one :class:`Patch` of its recent CVEs.
"""

from __future__ import annotations

import datetime as _dt
import urllib.parse
from typing import Any, Callable, Iterable, List, Optional

from ..models import Cve, Patch, severity_rank

SOURCE = "nvd"
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Curated third-party vendors worth tracking by default.
DEFAULT_VENDORS = [
    "Adobe", "Google Chrome", "Mozilla", "Cisco", "Fortinet", "Citrix",
    "Ivanti", "VMware", "Atlassian", "Zoom",
]

_SEVERITY_LABEL = {
    "CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low",
}


def query_url(vendor: str, start: _dt.datetime, end: _dt.datetime,
              results_per_page: int = 200) -> str:
    """Build an NVD query URL for one vendor over a date window."""
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params = {
        "keywordSearch": vendor,
        "pubStartDate": start.strftime(fmt),
        "pubEndDate": end.strftime(fmt),
        "resultsPerPage": results_per_page,
        "noRejected": "",
    }
    return BASE_URL + "?" + urllib.parse.urlencode(params)


def _best_metric(metrics: dict):
    """Return (base_score, severity_label) from the best available CVSS metric."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30",
                "cvssMetricV2"):
        for m in metrics.get(key, []) or []:
            data = m.get("cvssData") or {}
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or m.get("baseSeverity")
            if score is not None:
                label = _SEVERITY_LABEL.get((sev or "").upper())
                return float(score), label
    return None, None


def _english_desc(cve: dict) -> Optional[str]:
    for d in cve.get("descriptions", []) or []:
        if d.get("lang") == "en":
            text = (d.get("value") or "").strip()
            return text[:160] + ("…" if len(text) > 160 else "")
    return None


def parse_feed(
    data: Any,
    fetched_at: str,
    vendor_label: str,
    min_severity: str = "HIGH",
) -> List[Patch]:
    """Parse an NVD response for one vendor into a single :class:`Patch`.

    CVEs below ``min_severity`` (default HIGH) are dropped to cut noise.
    Returns an empty list when the vendor has no qualifying CVEs.
    """
    floor = severity_rank(min_severity)
    patch_id = f"nvd:{vendor_label}"
    cves: List[Cve] = []
    dates = []
    for item in data.get("vulnerabilities", []) or []:
        cve = item.get("cve") or {}
        cid = cve.get("id")
        if not cid:
            continue
        score, sev_label = _best_metric(cve.get("metrics") or {})
        if floor and severity_rank(sev_label) < floor:
            continue
        published = (cve.get("published") or "")[:10] or None
        if published:
            dates.append(published)
        cves.append(Cve(
            cve_id=cid,
            patch_id=patch_id,
            source=SOURCE,
            severity=sev_label,
            base_score=score,
            impact=_english_desc(cve),
            exploited=False,
            url=f"https://nvd.nist.gov/vuln/detail/{cid}",
            first_seen=published,
            products=[{"name": vendor_label, "kind": "other"}],
        ))

    if not cves:
        return []
    patch = Patch(
        source=SOURCE,
        patch_id=patch_id,
        title=vendor_label,
        product=vendor_label,
        version=None,
        release_date=max(dates) if dates else None,
        url=f"https://nvd.nist.gov/vuln/search/results?query="
            + urllib.parse.quote(vendor_label),
        fetched_at=fetched_at,
        cves=cves,
    )
    patch.recompute_severity()
    return [patch]


def fetch(
    http_get: Callable[[str], Any],
    fetched_at: str,
    vendors: Optional[Iterable[str]] = None,
    days: int = 30,
    min_severity: str = "HIGH",
    now: Optional[_dt.datetime] = None,
) -> List[Patch]:
    """Fetch recent high/critical CVEs for each vendor from NVD."""
    vendors = list(vendors) if vendors else DEFAULT_VENDORS
    now = now or _dt.datetime.now(_dt.timezone.utc)
    start = now - _dt.timedelta(days=days)
    patches: List[Patch] = []
    for vendor in vendors:
        data = http_get(query_url(vendor, start, now))
        patches.extend(parse_feed(data, fetched_at, vendor,
                                  min_severity=min_severity))
    return patches
