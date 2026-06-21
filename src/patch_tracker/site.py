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
from .patch_tuesday import patch_tuesday_for_update_id


def build_payload(
    db: Database,
    new_days: int = 7,
    now: Optional[_dt.datetime] = None,
) -> dict:
    """Build the dashboard payload dict from the database."""
    now = now or _dt.datetime.now(_dt.timezone.utc)
    cutoff = (now - _dt.timedelta(days=new_days)).date().isoformat()

    patches = []
    for p in db.list_patches():
        cve_rows = db.get_cves_for_patch(p["patch_id"])
        cves = []
        new_count = 0
        for c in cve_rows:
            is_new = bool(c["first_seen"] and c["first_seen"] >= cutoff)
            if is_new:
                new_count += 1
            cves.append({
                "cve_id": c["cve_id"],
                "severity": c["severity"],
                "base_score": c["base_score"],
                "exploited": bool(c["exploited"]),
                "publicly_disclosed": bool(c["publicly_disclosed"]),
                "impact": c["impact"],
                "url": c["url"],
                "first_seen": c["first_seen"],
                "is_new": is_new,
            })
        # For Microsoft, derive the Patch Tuesday date from the update id
        # (e.g. "2025-Jun") so the dashboard can label/sort by it.
        patch_tuesday = None
        if p["source"] == "microsoft":
            pt = patch_tuesday_for_update_id(p["version"] or "")
            if pt:
                patch_tuesday = pt.isoformat()

        patches.append({
            "patch_id": p["patch_id"],
            "source": p["source"],
            "title": p["title"],
            "product": p["product"],
            "version": p["version"],
            "release_date": p["release_date"],
            "patch_tuesday": patch_tuesday,
            "url": p["url"],
            "severity": p["severity"],
            "status": p["status"],
            "cve_count": p["cve_count"],
            "exploited_count": p["exploited_count"],
            "new_count": new_count,
            "cves": cves,
        })

    return {
        "generated_at": now.isoformat(timespec="seconds"),
        "new_window_days": new_days,
        "stats": db.stats(new_since=cutoff),
        "patches": patches,
    }


def write_site_data(db: Database, out_path: str, new_days: int = 7) -> dict:
    """Build the payload and write it to ``out_path`` as pretty JSON."""
    payload = build_payload(db, new_days=new_days)
    parent = os.path.dirname(os.path.abspath(out_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
        fh.write("\n")
    return payload
