"""Apple security data from the SOFA feed (https://sofa.macadmins.io).

SOFA ("Simple Organized Feed for Apple") publishes machine-readable JSON feeds
of Apple OS security releases. Each release lists the CVEs it fixes and which
of them are known to be actively exploited.

Feed layout (trimmed)::

    {
      "OSVersions": [
        {
          "OSVersion": "Sequoia 15",
          "Latest": { ... },
          "SecurityReleases": [
            {
              "UpdateName": "macOS Sequoia 15.5",
              "ProductName": "macOS Sequoia",
              "ProductVersion": "15.5",
              "ReleaseDate": "2025-05-12T00:00:00Z",
              "SecurityInfo": "https://support.apple.com/en-us/...",
              "CVEs": {"CVE-2025-31200": true, "CVE-2025-31201": false},
              "ActivelyExploitedCVEs": ["CVE-2025-31200"],
              "UniqueCVEsCount": 2
            }
          ]
        }
      ]
    }

We map each ``SecurityReleases`` entry to one :class:`Patch`. SOFA does not
provide a per-CVE severity, but it does flag actively-exploited CVEs, which is
the most operationally important signal for triage.
"""

from __future__ import annotations

from typing import Any, Callable, List

from ..models import Cve, Patch

SOURCE = "apple"
MACOS_FEED_URL = "https://sofafeed.macadmins.io/v1/macos_data_feed.json"
IOS_FEED_URL = "https://sofafeed.macadmins.io/v1/ios_data_feed.json"

FEED_URLS = {
    "macos": MACOS_FEED_URL,
    "ios": IOS_FEED_URL,
}


def parse_feed(data: Any, fetched_at: str) -> List[Patch]:
    """Parse a SOFA macOS/iOS data feed into :class:`Patch` records."""
    patches: List[Patch] = []
    seen_ids = set()
    for os_version in data.get("OSVersions", []) or []:
        for rel in os_version.get("SecurityReleases", []) or []:
            patch = _parse_release(rel, fetched_at)
            if patch is None or patch.patch_id in seen_ids:
                continue
            seen_ids.add(patch.patch_id)
            patches.append(patch)
    return patches


def _parse_release(rel: dict, fetched_at: str) -> Patch | None:
    update_name = rel.get("UpdateName") or rel.get("ProductVersion")
    if not update_name:
        return None

    patch_id = f"{SOURCE}:{update_name}"
    exploited = set(rel.get("ActivelyExploitedCVEs") or [])
    url = rel.get("SecurityInfo")
    # Derive recency from the release date (stateless: no persisted first_seen).
    first_seen = (rel.get("ReleaseDate") or "")[:10] or None

    cves: List[Cve] = []
    cve_map = rel.get("CVEs") or {}
    # ``CVEs`` is a dict {cve_id: actively_exploited_bool}; the explicit list
    # ``ActivelyExploitedCVEs`` is authoritative, so we union the two.
    for cve_id, flag in cve_map.items():
        cves.append(
            Cve(
                cve_id=cve_id,
                patch_id=patch_id,
                source=SOURCE,
                exploited=bool(flag) or cve_id in exploited,
                url=url,
                first_seen=first_seen,
            )
        )
    # Include any exploited CVE that somehow only appears in the list.
    for cve_id in exploited:
        if cve_id not in cve_map:
            cves.append(
                Cve(cve_id=cve_id, patch_id=patch_id, source=SOURCE,
                    first_seen=first_seen,
                    exploited=True, url=url)
            )

    return Patch(
        source=SOURCE,
        patch_id=patch_id,
        title=update_name,
        product=rel.get("ProductName"),
        version=rel.get("ProductVersion"),
        release_date=rel.get("ReleaseDate"),
        url=url,
        fetched_at=fetched_at,
        cves=cves,
    )


def fetch(
    http_get: Callable[[str], Any],
    fetched_at: str,
    platforms=("macos",),
) -> List[Patch]:
    """Fetch and parse the requested Apple platform feeds.

    ``http_get`` is any callable taking a URL and returning parsed JSON,
    allowing the network layer to be swapped for tests/offline use.
    """
    patches: List[Patch] = []
    for platform in platforms:
        url = FEED_URLS.get(platform)
        if not url:
            raise ValueError(f"Unknown Apple platform: {platform!r}")
        data = http_get(url)
        patches.extend(parse_feed(data, fetched_at))
    return patches
