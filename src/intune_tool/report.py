"""Rendering and export: tables, CSV/JSON, audit reports, change previews."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .assignments import ChangePlan
from .models import ResourceItem


# ---- row flattening ---------------------------------------------------
def flatten_rows(items: List[ResourceItem]) -> List[Dict[str, Any]]:
    """One row per assignment edge; unassigned resources get a single empty row."""
    rows: List[Dict[str, Any]] = []
    for it in items:
        if not it.assignments:
            rows.append(_base_row(it) | {"target": "(unassigned)"})
            continue
        for a in it.assignments:
            t = a.target
            rows.append(
                _base_row(it)
                | {
                    "target": t.display(),
                    "target_kind": t.kind,
                    "group_id": t.group_id or "",
                    "group_name": t.group_name or "",
                    "exclude": t.is_exclude,
                    "intent": a.intent or "",
                    "filter": t.filter_name or "",
                    "filter_type": t.filter_type if t.filter_id else "",
                }
            )
    return rows


def _base_row(it: ResourceItem) -> Dict[str, Any]:
    return {
        "area": it.area,
        "resource_type": it.resource_type,
        "resource_name": it.name,
        "resource_id": it.id,
        "platform": it.platform or "",
    }


# ---- text tables ------------------------------------------------------
def _table(headers: List[str], rows: List[List[str]]) -> str:
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(str(c)))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep = "  ".join("-" * widths[i] for i in range(len(headers)))
    body = "\n".join(
        "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(r)) for r in rows
    )
    return "\n".join([line, sep, body]) if rows else line + "\n" + sep + "\n(none)"


def render_assignments_table(items: List[ResourceItem]) -> str:
    by_area: Dict[str, List[ResourceItem]] = defaultdict(list)
    for it in items:
        by_area[it.area].append(it)
    out: List[str] = []
    for area in sorted(by_area):
        out.append(f"\n=== {area} ===")
        rows = []
        for it in sorted(by_area[area], key=lambda x: x.name.lower()):
            if not it.assignments:
                rows.append([it.name, it.platform or "", "(unassigned)"])
            else:
                first = True
                for a in it.assignments:
                    rows.append([
                        it.name if first else "",
                        (it.platform or "") if first else "",
                        a.target.display() + (f"  ⟶ {a.intent}" if a.intent else ""),
                    ])
                    first = False
        out.append(_table(["Resource", "Platform", "Assigned to"], rows))
    return "\n".join(out)


def render_group_report(group_name: str, group_id: str, hits: List[Tuple]) -> str:
    out = [f"Group: {group_name}  ({group_id})",
           f"Assigned to {len(hits)} resource(s):", ""]
    by_area: Dict[str, List[Tuple]] = defaultdict(list)
    for it, edges in hits:
        by_area[it.area].append((it, edges))
    for area in sorted(by_area):
        out.append(f"=== {area} ===")
        rows = []
        for it, edges in sorted(by_area[area], key=lambda x: x[0].name.lower()):
            for e in edges:
                kind = "EXCLUDE" if e.target.is_exclude else "include"
                extras = []
                if e.intent:
                    extras.append(e.intent)
                if e.target.filter_id:
                    extras.append(f"filter {e.target.filter_type}:{e.target.filter_name}")
                rows.append([it.name, kind, ", ".join(extras)])
        out.append(_table(["Resource", "Mode", "Notes"], rows))
        out.append("")
    return "\n".join(out)


# ---- exports ----------------------------------------------------------
def to_csv(items: List[ResourceItem]) -> str:
    rows = flatten_rows(items)
    fields = [
        "area", "resource_type", "resource_name", "resource_id", "platform",
        "target", "target_kind", "group_name", "group_id", "exclude",
        "intent", "filter", "filter_type",
    ]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue()


def to_json(items: List[ResourceItem]) -> str:
    payload = []
    for it in items:
        payload.append(
            {
                "area": it.area,
                "resource_type": it.resource_type,
                "id": it.id,
                "name": it.name,
                "platform": it.platform,
                "assignments": [
                    {
                        "kind": a.target.kind,
                        "group_id": a.target.group_id,
                        "group_name": a.target.group_name,
                        "exclude": a.target.is_exclude,
                        "intent": a.intent,
                        "filter_id": a.target.filter_id,
                        "filter_name": a.target.filter_name,
                        "filter_type": a.target.filter_type if a.target.filter_id else None,
                        "settings": a.settings,
                    }
                    for a in it.assignments
                ],
            }
        )
    return json.dumps(payload, indent=2)


# ---- audit ------------------------------------------------------------
def render_audit(items: List[ResourceItem]) -> str:
    total = len(items)
    assigned = [it for it in items if it.assignments]
    unassigned = [it for it in items if not it.assignments]
    edges = [a for it in items for a in it.assignments]
    group_usage: Counter = Counter()
    filter_usage: Counter = Counter()
    virtual = Counter()
    excludes = 0
    for it in items:
        for a in it.assignments:
            t = a.target
            if t.is_exclude:
                excludes += 1
            if t.is_virtual:
                virtual[t.display()] += 1
            elif t.group_id:
                group_usage[t.group_name or t.group_id] += 1
            if t.filter_id:
                filter_usage[t.filter_name or t.filter_id] += 1

    out = ["INTUNE ASSIGNMENT AUDIT", "=" * 60, ""]
    out.append(f"Resources scanned : {total}")
    out.append(f"  assigned        : {len(assigned)}")
    out.append(f"  unassigned      : {len(unassigned)}")
    out.append(f"Assignment edges  : {len(edges)}")
    out.append(f"  exclusions      : {excludes}")
    out.append("")
    out.append("By area:")
    area_counts: Counter = Counter(it.area for it in items)
    area_assigned: Counter = Counter(it.area for it in assigned)
    for area in sorted(area_counts):
        out.append(f"  {area:<22} {area_assigned[area]:>3} assigned / {area_counts[area]:>3} total")
    out.append("")
    out.append("Virtual targets:")
    out += [f"  {name:<40} {n}" for name, n in virtual.most_common()] or ["  (none)"]
    out.append("")
    out.append(f"Most-assigned groups (top 20 of {len(group_usage)}):")
    out += [f"  {name:<45} {n}" for name, n in group_usage.most_common(20)] or ["  (none)"]
    out.append("")
    out.append(f"Assignment filters in use ({len(filter_usage)}):")
    out += [f"  {name:<45} {n}" for name, n in filter_usage.most_common()] or ["  (none)"]
    out.append("")
    if unassigned:
        out.append(f"Unassigned resources ({len(unassigned)}):")
        for it in sorted(unassigned, key=lambda x: (x.area, x.name.lower())):
            out.append(f"  [{it.area}] {it.name}")
    return "\n".join(out)


# ---- change plans -----------------------------------------------------
def render_change_plans(plans: List[ChangePlan], *, dry_run: bool) -> str:
    if not plans:
        return "No changes — nothing matched."
    header = "PLANNED CHANGES (dry-run, nothing written)" if dry_run else "CHANGES"
    out = [header, "=" * 60]
    changed = [p for p in plans if p.added]
    skipped = [p for p in plans if p.skipped_reason]
    failed = [p for p in plans if p.error]
    for p in changed:
        status = "DRY-RUN" if dry_run else ("OK" if p.applied else "FAILED")
        out.append(f"[{status}] {p.area} / {p.resource_name}")
        for d in p.added:
            out.append(f"    + {d}")
        if p.error:
            out.append(f"    ! {p.error}")
    out.append("")
    out.append(
        f"{len(changed)} resource(s) {'to change' if dry_run else 'changed'}, "
        f"{len(skipped)} skipped, {len(failed)} failed."
    )
    if skipped:
        out.append("Skipped:")
        for p in skipped:
            out.append(f"  - {p.area} / {p.resource_name}: {p.skipped_reason}")
    return "\n".join(out)
