"""Third-party zero-days from the CISA Known Exploited Vulnerabilities catalog.

CISA's KEV catalog (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
is the authoritative, free, machine-readable feed of vulnerabilities with
confirmed in-the-wild exploitation across *all* vendors -- browsers (Chrome,
Edge, Firefox), Adobe, Cisco, Ivanti, and more. Every entry is by definition
actively exploited, which makes it ideal for a "third-party / zero-day"
section alongside the Apple and Microsoft OS feeds.

Feed layout (trimmed)::

    {
      "catalogVersion": "2025.06.10",
      "dateReleased": "2025-06-10T...",
      "vulnerabilities": [
        {
          "cveID": "CVE-2025-5419",
          "vendorProject": "Google",
          "product": "Chromium V8",
          "vulnerabilityName": "Google Chromium V8 OOB R/W Vulnerability",
          "dateAdded": "2025-06-05",
          "shortDescription": "...",
          "requiredAction": "Apply mitigations per vendor instructions...",
          "dueDate": "2025-06-26",
          "knownRansomwareCampaignUse": "Unknown"
        }
      ]
    }

Entries are grouped per ``vendorProject + product`` into one :class:`Patch`,
so the dashboard shows e.g. "Google — Chromium V8" with its exploited CVEs.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, List, Optional

from ..models import Cve, Patch

SOURCE = "cisa-kev"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")

# OS vendors already covered by the dedicated Apple/Microsoft feeds; excluded
# by default so the KEV section focuses on third-party software.
_OS_VENDORS = {"microsoft", "apple"}


def parse_feed(
    data: Any,
    fetched_at: str,
    vendors: Optional[Iterable[str]] = None,
    include_os_vendors: bool = False,
) -> List[Patch]:
    """Parse the KEV catalog into per vendor+product :class:`Patch` records.

    ``vendors`` optionally restricts to specific vendor names (case-insensitive,
    e.g. ``{"google", "mozilla"}``).
    """
    want = {v.lower() for v in vendors} if vendors else None
    groups: dict = {}
    for item in data.get("vulnerabilities", []) or []:
        cve_id = item.get("cveID")
        if not cve_id:
            continue
        vendor = (item.get("vendorProject") or "Unknown").strip()
        product = (item.get("product") or "").strip()
        if want is not None and vendor.lower() not in want:
            continue
        if want is None and not include_os_vendors and vendor.lower() in _OS_VENDORS:
            continue
        groups.setdefault((vendor, product), []).append(item)

    patches: List[Patch] = []
    for (vendor, product), items in groups.items():
        label = f"{vendor} {product}".strip()
        patch_id = f"kev:{vendor}:{product}".rstrip(":")
        dates = [i.get("dateAdded") for i in items if i.get("dateAdded")]
        release = max(dates) if dates else None

        cves: List[Cve] = []
        for i in items:
            ransomware = (i.get("knownRansomwareCampaignUse") or "").lower() == "known"
            cves.append(Cve(
                cve_id=i["cveID"],
                patch_id=patch_id,
                source=SOURCE,
                # KEV doesn't carry CVSS; flag ransomware-linked as Critical.
                severity="Critical" if ransomware else None,
                impact=i.get("vulnerabilityName"),
                exploited=True,                 # KEV == exploited in the wild
                publicly_disclosed=True,
                url=f"https://nvd.nist.gov/vuln/detail/{i['cveID']}",
                first_seen=i.get("dateAdded"),
                products=[{"name": label, "kind": "other"}],
            ))

        patches.append(Patch(
            source=SOURCE,
            patch_id=patch_id,
            title=label,
            product=vendor,            # used as the dashboard "platform"/vendor
            version=None,
            release_date=release,
            url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            fetched_at=fetched_at,
            cves=cves,
        ))
    return patches


def fetch(
    http_get: Callable[[str], Any],
    fetched_at: str,
    vendors: Optional[Iterable[str]] = None,
    include_os_vendors: bool = False,
) -> List[Patch]:
    """Fetch and parse the CISA KEV catalog."""
    data = http_get(KEV_URL)
    return parse_feed(data, fetched_at, vendors=vendors,
                      include_os_vendors=include_os_vendors)
