"""Generate the static JSON dataset consumed by the web dashboard.

The web app is a static site: a GitHub Actions workflow refreshes the SQLite
database from the live feeds on a daily schedule, calls :func:`build_payload`
to serialize it into ``web/data.json``, then publishes ``web/`` to GitHub
Pages. Keeping the dataset as a single static JSON file means the site needs
no backend at all.

A CVE is flagged ``is_new`` when its ``first_seen`` date (persisted in the
committed database) falls within ``new_days`` of the build time -- that is how
the dashboard surfaces CVEs that were released since the last run.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from typing import Optional

from .db import Database
from .models import severity_rank
from .patch_tuesday import patch_tuesday_for_update_id

_SEV_POINTS = {4: 40, 3: 28, 2: 14, 1: 5, 0: 0}


def _priority_score(severity, exploited_count, new_count, max_cvss,
                    ransomware_count, earliest_due, now) -> dict:
    """Compute a 0-100 remediation-priority score and band with reasons.

    Models how a vulnerability-management engineer triages: active
    exploitation and ransomware dominate, then CVSS/severity, then recency and
    any CISA KEV deadline (overdue items are escalated hard).
    """
    score = 0
    reasons = []
    score += _SEV_POINTS.get(severity_rank(severity), 0)
    if max_cvss:
        score += round(max_cvss * 2)            # 0-20
    if exploited_count:
        score += 45
        reasons.append("actively exploited")
    if ransomware_count:
        score += 12
        reasons.append("ransomware-linked")
    if new_count:
        score += 15
        reasons.append("newly released")
    if severity_rank(severity) >= 4:
        reasons.append("critical severity")
    if earliest_due:
        try:
            due = _dt.date.fromisoformat(earliest_due[:10])
            days = (due - now.date()).days
            if days < 0:
                score += 25
                reasons.append(f"KEV overdue by {-days}d")
            elif days <= 7:
                score += 12
                reasons.append(f"KEV due in {days}d")
        except ValueError:
            pass
    score = max(0, min(100, score))
    band = ("critical" if score >= 70 else "high" if score >= 45
            else "medium" if score >= 20 else "low")
    return {"score": score, "band": band, "reasons": reasons[:4]}

# Windows hotpatch baseline months: Jan/Apr/Jul/Oct ship a full cumulative
# update (reboot); the two months in between are hotpatch-only (no reboot) for
# enrolled SKUs.
_HOTPATCH_BASELINE_MONTHS = {1, 4, 7, 10}
_HOTPATCH_SKUS = ("Windows 11 Enterprise 24H2 · "
                  "Windows Server 2025 (Azure-enrolled)")


def windows_servicing(update_id: str) -> dict:
    """Describe the Windows servicing channel for an MSRC monthly update.

    MSRC publishes only the **B release** (Patch Tuesday, the cumulative
    security update). Optional non-security **C** (3rd week) and **D** (4th
    week) preview releases are not security updates and are not tracked here.
    For hotpatch-enrolled SKUs we also flag whether this is a *baseline*
    (cumulative, reboot) month or a *hotpatch* (no-reboot) month.
    """
    pt = patch_tuesday_for_update_id(update_id)
    month = pt.month if pt else None
    is_baseline = month in _HOTPATCH_BASELINE_MONTHS if month else True
    if is_baseline:
        hotpatch = {
            "is_hotpatch_month": False,
            "update_type": "Cumulative (hotpatch baseline)",
            "reboot_required": True,
            "note": ("Quarterly hotpatch baseline — even hotpatch-enrolled "
                     "devices install the full cumulative update and must "
                     "reboot this month."),
        }
    else:
        hotpatch = {
            "is_hotpatch_month": True,
            "update_type": "Hotpatch (no reboot for enrolled SKUs)",
            "reboot_required": False,
            "note": ("Hotpatch month — enrolled " + _HOTPATCH_SKUS + " apply "
                     "this security update without rebooting; all other "
                     "systems receive the standard cumulative update (reboot "
                     "required)."),
        }
    return {
        "channel": "B",
        "channel_label": "B release — Patch Tuesday (cumulative security)",
        "is_cumulative": True,
        "eligible_skus": _HOTPATCH_SKUS,
        "hotpatch": hotpatch,
        "preview_note": ("Optional non-security 'C' (3rd-week) and 'D' "
                         "(4th-week) preview releases are not tracked here."),
    }


_UPDATE_PATH = {
    "macOS": "System Settings ▸ General ▸ Software Update",
    "iOS": "Settings ▸ General ▸ Software Update",
    "iPadOS": "Settings ▸ General ▸ Software Update",
    "tvOS": "Settings ▸ System ▸ Software Updates",
    "watchOS": "Watch app ▸ General ▸ Software Update",
}


def remediation_for(
    source: str,
    platform: str,
    product: Optional[str],
    version: Optional[str],
    title: str,
    url: Optional[str],
    exploited_count: int,
    severity: Optional[str],
    affected: Optional[dict] = None,
) -> dict:
    """Build detailed, source-appropriate remediation guidance for a patch.

    Returns a dict with a ``summary``, an ``urgency``
    (``critical``/``high``/``normal``) and ``note`` derived from exploitation
    and severity, action ``links``, and audience-specific ``sections`` -- for
    Microsoft these split Windows **client** (workstation) vs **server**
    guidance so each team gets the steps that apply to them.
    """
    affected = affected or {}
    links = []
    sections = []

    if source == "microsoft":
        n_client = affected.get("client", 0)
        n_server = affected.get("server", 0)
        n_other = affected.get("other", 0)
        bits = []
        if n_client:
            bits.append(f"{n_client} affecting Windows clients")
        if n_server:
            bits.append(f"{n_server} affecting Windows Server")
        if n_other:
            bits.append(f"{n_other} affecting other Microsoft products")
        scope = ("; ".join(bits)) if bits else "all affected systems"
        summary = f"Apply the {title} ({scope})."

        if n_client or not (n_server or n_other):
            sections.append({
                "audience": "Windows clients (desktops & laptops)",
                "icon": "💻",
                "steps": [
                    "Managed fleets: deploy via Windows Update for Business or "
                    "Microsoft Intune update rings with an install deadline and "
                    "enforced reboot; validate on a pilot ring first.",
                    "Standalone/home devices: Settings ▸ Windows Update ▸ "
                    "Check for updates ▸ Install, then restart.",
                    "Watch for application-compatibility regressions before "
                    "broad rollout; keep the previous cumulative update on hand "
                    "for rollback.",
                ],
            })
        if n_server:
            sections.append({
                "audience": "Windows Server",
                "icon": "🖥️",
                "steps": [
                    "Schedule a maintenance window — servers require a reboot "
                    "to finish installation.",
                    "Deploy via WSUS, Configuration Manager (SCCM), or Azure "
                    "Update Manager; for failover clusters use Cluster-Aware "
                    "Updating to patch nodes without downtime.",
                    "Role-sensitive hosts (Domain Controllers, Exchange, SQL): "
                    "back up first and follow role-specific patch ordering.",
                    "After reboot, confirm critical services and the OS build "
                    "number.",
                ],
            })
        sections.append({
            "audience": "Update management (all)",
            "icon": "📦",
            "steps": [
                "For offline/air-gapped systems, download the specific KB from "
                "the Microsoft Update Catalog and import it into your tooling.",
                "Track deployment per ring and prioritise Critical and "
                "actively-exploited CVEs for emergency change.",
            ],
        })
        # The MSRC release-notes page lists every CVE in the month with direct
        # KB / Update Catalog links. (A catalog search by month id like
        # "2025-Jun" returns nothing — the catalog is keyed by KB number, which
        # lives on the per-CVE MSRC pages, so we link there instead.)
        release_note = (f"https://msrc.microsoft.com/update-guide/releaseNote/"
                        f"{version}" if version else
                        "https://msrc.microsoft.com/update-guide")
        links.append({"label": "MSRC release notes", "url": release_note})
    elif source == "cisa-kev":
        summary = (f"{title} has a vulnerability on CISA's Known Exploited "
                   "Vulnerabilities catalog — update to the vendor's patched "
                   "release as an emergency.")
        sections.append({
            "audience": f"{title} (all installs)",
            "icon": "🌐",
            "steps": [
                "Upgrade to the latest vendor-patched version. Browsers "
                "(Chrome, Edge, Firefox) self-update on relaunch — force a "
                "restart of the app to apply it.",
                "Managed fleets: push the patched build via your deployment "
                "tool (Intune, Jamf, SCCM, WSUS-imported) and enforce an app "
                "restart; block older versions where possible.",
                "Per CISA BOD 22-01, remediate by the catalog due date; given "
                "confirmed in-the-wild exploitation, treat as an emergency "
                "change regardless.",
            ],
        })
        links.append({
            "label": "CISA KEV catalog",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        })
    elif source == "nvd":
        summary = (f"Patch {title} to the vendor's fixed release "
                   "(recent high/critical CVEs from NVD).")
        sections.append({
            "audience": f"{title} (all installs)",
            "icon": "🧩",
            "steps": [
                "Identify affected versions in your estate (software inventory "
                "/ SBOM) and upgrade to the vendor's patched build.",
                "Managed fleets: deploy via your software-deployment tool "
                "(Intune, Jamf, SCCM, WSUS-imported) and enforce an app "
                "restart; remove end-of-life versions.",
                "Subscribe to the vendor's PSIRT/security advisories so future "
                "fixes are caught early; prioritise internet-facing systems.",
            ],
        })
        if url:
            links.append({"label": "NVD advisories", "url": url})
    elif source == "apple":
        target = (f"{product} {version}".strip() if product else title) or title
        path = _UPDATE_PATH.get(platform, "Software Update")
        summary = f"Update affected {platform} devices to {target}."
        sections.append({
            "audience": f"All affected {platform} devices",
            "icon": "📱" if platform in ("iOS", "iPadOS") else "💻",
            "steps": [
                f"On the device: {path} — install {target} and restart if "
                "prompted.",
                "Managed fleets: push the update via MDM (Jamf, Kandji, Intune, "
                "Mosyle…) or a software-update enforcement / deferral policy "
                "with a deadline.",
                "Confirm the OS build matches the fixed version afterwards; "
                "remind users that a restart is required for kernel fixes.",
            ],
        })
        if url:
            links.append({"label": "Apple security release notes", "url": url})

    if exploited_count:
        urgency = "critical"
        note = (f"{exploited_count} CVE(s) are being actively exploited — patch "
                "immediately, out-of-band if necessary.")
    elif (severity or "").lower() == "critical":
        urgency = "high"
        note = "Critical-severity fixes included — schedule promptly."
    else:
        urgency = "normal"
        note = "Apply within your normal patch cycle."

    return {"summary": summary, "urgency": urgency, "note": note,
            "links": links, "sections": sections}


def platform_for(source: str, product: Optional[str], title: Optional[str]) -> str:
    """Derive a coarse platform label used by the dashboard's platform filter."""
    if source == "microsoft":
        return "Windows"
    if source == "cisa-kev":
        # For third-party zero-days the vendor is the most useful grouping.
        return product or "Third-party"
    if source == "nvd":
        return product or title or "Third-party"
    text = f"{product or ''} {title or ''}".lower()
    if "ipados" in text:
        return "iPadOS"
    if "ios" in text:
        return "iOS"
    if "tvos" in text:
        return "tvOS"
    if "watchos" in text:
        return "watchOS"
    if "visionos" in text:
        return "visionOS"
    if "safari" in text:
        return "Safari"
    return "macOS"


def _windowed(patches: list, window_days: int, now: _dt.datetime) -> list:
    """Apply a source-aware recency window.

    Microsoft ships monthly, so we always keep the **latest** monthly rollup
    (regardless of how far into the cycle we are). Apple/NVD/CISA-KEV land any
    day, so we keep items released/added within the last ``window_days``.
    """
    cutoff = (now - _dt.timedelta(days=window_days)).date().isoformat()
    ms_dates = [p["release_date"] for p in patches
                if p["source"] == "microsoft" and p["release_date"]]
    latest_ms = max(ms_dates) if ms_dates else None
    out = []
    for p in patches:
        if p["source"] == "microsoft":
            if latest_ms is None or (p["release_date"] or "") >= latest_ms:
                out.append(p)
        else:
            rd = (p["release_date"] or "")[:10]
            if not rd or rd >= cutoff:
                out.append(p)
    return out


def _compute_stats(patches: list) -> dict:
    """Summary counts computed from the (windowed) patch set shown."""
    cve_ids, exploited, new = set(), set(), set()
    by_source, by_severity, by_status = {}, {}, {}
    kinds = {"client": set(), "server": set(), "other": set()}
    for p in patches:
        by_source[p["source"]] = by_source.get(p["source"], 0) + 1
        sev = p["severity"] or "unknown"
        by_severity[sev] = by_severity.get(sev, 0) + 1
        st = p["status"] or "new"
        by_status[st] = by_status.get(st, 0) + 1
        for c in p["cves"]:
            cve_ids.add(c["cve_id"])
            if c["exploited"]:
                exploited.add(c["cve_id"])
            if c["is_new"]:
                new.add(c["cve_id"])
            for k in c["product_kinds"]:
                if k in kinds:
                    kinds[k].add(c["cve_id"])
    return {
        "total_patches": len(patches),
        "total_cves": len(cve_ids),
        "exploited_cves": len(exploited),
        "new_cves": len(new),
        "by_source": by_source,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_product_kind": {k: len(v) for k, v in kinds.items() if v},
    }


def build_payload(
    db: Database,
    new_days: int = 7,
    now: Optional[_dt.datetime] = None,
    window_days: int = 30,
) -> dict:
    """Build the dashboard payload dict from the database.

    ``window_days`` scopes the board to recent activity (default ~1 month),
    source-aware: the latest monthly Microsoft rollup is always kept, while
    Apple/NVD/CISA-KEV items must fall within the window. Stats reflect the
    windowed set so the KPIs match what's listed.
    """
    now = now or _dt.datetime.now(_dt.timezone.utc)
    cutoff = (now - _dt.timedelta(days=new_days)).date().isoformat()

    patches = []
    for p in db.list_patches():
        # Group affected products by CVE so each CVE can show which platforms
        # (Windows client vs server, etc.) it hits, and the patch can report a
        # client/server breakdown.
        prod_by_cve: dict = {}
        for pr in db.get_products_for_patch(p["patch_id"]):
            prod_by_cve.setdefault(pr["cve_id"], []).append(
                {"name": pr["name"], "kind": pr["kind"]})

        cve_rows = db.get_cves_for_patch(p["patch_id"])
        cves = []
        new_count = 0
        affected = {"client": 0, "server": 0, "other": 0}
        for c in cve_rows:
            is_new = bool(c["first_seen"] and c["first_seen"] >= cutoff)
            if is_new:
                new_count += 1
            prods = prod_by_cve.get(c["cve_id"], [])
            kinds = sorted({pr["kind"] for pr in prods})
            for k in ("client", "server", "other"):
                if k in kinds:
                    affected[k] += 1
            cves.append({
                "cve_id": c["cve_id"],
                "severity": c["severity"],
                "base_score": c["base_score"],
                "exploited": bool(c["exploited"]),
                "publicly_disclosed": bool(c["publicly_disclosed"]),
                "impact": c["impact"],
                "url": c["url"],
                "first_seen": c["first_seen"],
                "due_date": c["due_date"],
                "ransomware": bool(c["ransomware"]),
                "is_new": is_new,
                "product_kinds": kinds,
                "products": [pr["name"] for pr in prods],
            })

        platform = platform_for(p["source"], p["product"], p["title"])

        patch_tuesday = None
        servicing = None
        if p["source"] == "microsoft":
            pt = patch_tuesday_for_update_id(p["version"] or "")
            if pt:
                patch_tuesday = pt.isoformat()
            servicing = windows_servicing(p["version"] or "")

        remediation = remediation_for(
            p["source"], platform, p["product"], p["version"], p["title"],
            p["url"], p["exploited_count"], p["severity"], affected,
        )

        due_dates = [c["due_date"] for c in cves if c["due_date"]]
        ransomware_count = sum(1 for c in cves if c["ransomware"])
        disclosed_count = sum(1 for c in cves if c["publicly_disclosed"])
        max_cvss = max((c["base_score"] for c in cves
                        if c["base_score"] is not None), default=None)
        priority = _priority_score(
            p["severity"], p["exploited_count"], new_count, max_cvss,
            ransomware_count, min(due_dates) if due_dates else None, now,
        )

        patches.append({
            "patch_id": p["patch_id"],
            "source": p["source"],
            "platform": platform,
            "title": p["title"],
            "product": p["product"],
            "version": p["version"],
            "release_date": p["release_date"],
            "patch_tuesday": patch_tuesday,
            "servicing": servicing,
            "url": p["url"],
            "severity": p["severity"],
            "status": p["status"],
            "cve_count": p["cve_count"],
            "exploited_count": p["exploited_count"],
            "new_count": new_count,
            "ransomware_count": ransomware_count,
            "disclosed_count": disclosed_count,
            "max_cvss": max_cvss,
            "due_date": min(due_dates) if due_dates else None,
            "priority": priority,
            "affected": affected,
            "remediation": remediation,
            "cves": cves,
        })

    patches = _windowed(patches, window_days, now)

    return {
        "generated_at": now.isoformat(timespec="seconds"),
        "new_window_days": new_days,
        "window_days": window_days,
        "stats": _compute_stats(patches),
        "patches": patches,
    }


def write_site_data(db: Database, out_path: str, new_days: int = 7,
                    window_days: int = 30) -> dict:
    """Build the payload and write it to ``out_path`` as pretty JSON."""
    payload = build_payload(db, new_days=new_days, window_days=window_days)
    parent = os.path.dirname(os.path.abspath(out_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
        fh.write("\n")
    return payload
