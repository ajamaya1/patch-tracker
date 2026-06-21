"""Microsoft security updates from the MSRC CVRF v3.0 API.

See https://github.com/Microsoft/MSRC-Microsoft-Security-Updates-API.

Two endpoints are used:

* ``GET /cvrf/v3.0/updates`` -> a list of monthly update summaries::

      {"value": [
        {"ID": "2025-Jun", "Alias": "2025-Jun",
         "DocumentTitle": "June 2025 Security Updates",
         "CurrentReleaseDate": "2025-06-10T07:00:00Z",
         "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/document/2025-Jun"}
      ]}

* ``GET /cvrf/v3.0/cvrf/{ID}`` -> a full CVRF document whose ``Vulnerability``
  array holds one entry per CVE. Within each vulnerability the ``Threats``
  array encodes severity and exploitability via a ``Type`` discriminator:

      Type 0 = Impact (e.g. "Remote Code Execution")
      Type 1 = Exploit status ("Publicly Disclosed:No;Exploited:Yes;...")
      Type 3 = Severity ("Critical" / "Important" / "Moderate" / "Low")

We model each monthly update as one :class:`Patch` containing all its CVEs.
"""

from __future__ import annotations

from typing import Any, Callable, List, Optional

from ..models import Cve, Patch

SOURCE = "microsoft"
BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0"
UPDATES_URL = f"{BASE_URL}/updates"

# MSRC CVRF Threat.Type discriminators.
THREAT_IMPACT = 0
THREAT_EXPLOIT = 1
THREAT_SEVERITY = 3


def classify_product(name: str) -> str:
    """Classify an affected product name as client / server / other.

    Windows Server SKUs -> ``server``; other Windows desktop SKUs (10, 11,
    7/8.1, etc.) -> ``client``; everything else (Office, Edge, .NET, SQL …)
    -> ``other``.
    """
    n = (name or "").lower()
    if "server" in n:
        return "server"
    if "windows" in n:
        return "client"
    return "other"


def _product_name_map(doc: dict) -> dict:
    """Map ProductID -> product name from the CVRF ProductTree."""
    tree = doc.get("ProductTree") or {}
    out = {}
    for fp in tree.get("FullProductName", []) or []:
        pid = fp.get("ProductID")
        if pid is not None:
            out[str(pid)] = fp.get("Value") or str(pid)
    return out


def _affected_products(vuln: dict, name_map: dict) -> list:
    """Return [{'name', 'kind'}] for products this vuln is known to affect.

    ProductStatuses Type 3 == "Known Affected".
    """
    seen = {}
    for status in vuln.get("ProductStatuses", []) or []:
        if status.get("Type") != 3:
            continue
        for pid in status.get("ProductID", []) or []:
            name = name_map.get(str(pid))
            if name and name not in seen:
                seen[name] = {"name": name, "kind": classify_product(name)}
    return list(seen.values())


def cvrf_url(update_id: str) -> str:
    """The CVRF document URL for a given monthly update id (e.g. 2025-Jun)."""
    return f"{BASE_URL}/cvrf/{update_id}"


def parse_updates(data: Any) -> List[dict]:
    """Parse the ``/updates`` summary list into plain dicts.

    Returns dicts with ``id``, ``title``, ``release_date`` and ``url`` keys.
    """
    out: List[dict] = []
    for item in data.get("value", []) or []:
        update_id = item.get("ID") or item.get("Alias")
        if not update_id:
            continue
        out.append(
            {
                "id": update_id,
                "title": item.get("DocumentTitle") or update_id,
                "release_date": item.get("CurrentReleaseDate")
                or item.get("InitialReleaseDate"),
                "url": item.get("CvrfUrl") or cvrf_url(update_id),
            }
        )
    return out


def _threat_value(threats, threat_type: int) -> Optional[str]:
    """Return the first threat Description value matching ``threat_type``."""
    for threat in threats or []:
        if threat.get("Type") == threat_type:
            desc = (threat.get("Description") or {}).get("Value")
            if desc:
                return desc
    return None


def _max_base_score(vuln: dict) -> Optional[float]:
    scores = []
    for s in vuln.get("CVSSScoreSets", []) or []:
        val = s.get("BaseScore")
        if isinstance(val, (int, float)):
            scores.append(float(val))
    return max(scores) if scores else None


def _exploit_flags(threats) -> tuple[bool, bool]:
    """Return (exploited, publicly_disclosed) parsed from a Type 1 threat.

    The description is a semicolon-delimited string such as
    ``"Publicly Disclosed:No;Exploited:Yes;Latest Software Release:..."``.
    """
    raw = _threat_value(threats, THREAT_EXPLOIT) or ""
    exploited = False
    disclosed = False
    for part in raw.split(";"):
        key, _, value = part.partition(":")
        key = key.strip().lower()
        value = value.strip().lower()
        if key == "exploited":
            exploited = value.startswith("yes")
        elif key == "publicly disclosed":
            disclosed = value.startswith("yes")
    return exploited, disclosed


def parse_cvrf(summary: dict, doc: Any, fetched_at: str) -> Patch:
    """Parse one CVRF document into a :class:`Patch` with its CVEs."""
    update_id = summary["id"]
    patch_id = f"msrc:{update_id}"
    patch = Patch(
        source=SOURCE,
        patch_id=patch_id,
        title=summary.get("title") or update_id,
        product="Microsoft Security Update",
        version=update_id,
        release_date=summary.get("release_date"),
        url=summary.get("url"),
        fetched_at=fetched_at,
    )

    name_map = _product_name_map(doc)
    for vuln in doc.get("Vulnerability", []) or []:
        cve_id = vuln.get("CVE")
        if not cve_id:
            continue
        threats = vuln.get("Threats", [])
        exploited, disclosed = _exploit_flags(threats)
        patch.cves.append(
            Cve(
                cve_id=cve_id,
                patch_id=patch_id,
                source=SOURCE,
                severity=_threat_value(threats, THREAT_SEVERITY),
                impact=_threat_value(threats, THREAT_IMPACT),
                base_score=_max_base_score(vuln),
                exploited=exploited,
                publicly_disclosed=disclosed,
                url=f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
                products=_affected_products(vuln, name_map),
            )
        )

    patch.recompute_severity()
    return patch


def fetch(
    http_get: Callable[[str], Any],
    fetched_at: str,
    months: int = 3,
) -> List[Patch]:
    """Fetch the most recent ``months`` monthly updates and their CVEs."""
    summaries = parse_updates(http_get(UPDATES_URL))
    # The API returns updates in chronological order; take the most recent.
    summaries = sorted(
        summaries, key=lambda s: s.get("release_date") or "", reverse=True
    )[: max(months, 0)]

    patches: List[Patch] = []
    for summary in summaries:
        doc = http_get(summary["url"])
        patches.append(parse_cvrf(summary, doc, fetched_at))
    return patches
