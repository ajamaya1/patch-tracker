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
def render_audit(items: List[ResourceItem], empty_groups: Optional[List[dict]] = None) -> str:
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
    if empty_groups:
        out.append(f"⚠ Empty groups targeted by assignments ({len(empty_groups)}):")
        for e in empty_groups:
            out.append(f"  {e['group_name']:<45} → {len(e['resources'])} resource(s)")
        out.append("")
    if unassigned:
        out.append(f"Unassigned resources ({len(unassigned)}):")
        for it in sorted(unassigned, key=lambda x: (x.area, x.name.lower())):
            out.append(f"  [{it.area}] {it.name}")
    return "\n".join(out)


# ---- compare two groups ----------------------------------------------
def render_compare(a_name: str, b_name: str, cmp: dict) -> str:
    out = [f"ASSIGNMENT COMPARISON", "=" * 60,
           f"A = {a_name}", f"B = {b_name}", ""]

    def _section(title, rows, fmt):
        out.append(f"{title} ({len(rows)}):")
        if not rows:
            out.append("  (none)")
        for r in sorted(rows, key=lambda x: (x["item"].area, x["item"].name.lower())):
            out.append("  " + fmt(r))
        out.append("")

    _section("Only in A (would be mirrored to B)", cmp["only_a"],
             lambda r: f"[{r['item'].area}] {r['item'].name}  ({r['a_mode']})")
    _section("Only in B", cmp["only_b"],
             lambda r: f"[{r['item'].area}] {r['item'].name}  ({r['b_mode']})")
    _section("In both", cmp["both"],
             lambda r: f"[{r['item'].area}] {r['item'].name}  (A:{r['a_mode']} / B:{r['b_mode']})")
    if cmp["conflict"]:
        _section("⚠ Conflicts (include vs exclude)", cmp["conflict"],
                 lambda r: f"[{r['item'].area}] {r['item'].name}  (A:{r['a_mode']} / B:{r['b_mode']})")
    return "\n".join(out)


# ---- effective (what-if) ---------------------------------------------
def render_effective(subject: str, kind: str, rows: List[dict]) -> str:
    applied = [r for r in rows if not r["excluded"]]
    excluded = [r for r in rows if r["excluded"]]
    out = [f"EFFECTIVE ASSIGNMENTS ({kind})", "=" * 60,
           f"Subject: {subject}",
           f"{len(applied)} effective, {len(excluded)} blocked by exclusion", ""]
    by_area: Dict[str, List[dict]] = defaultdict(list)
    for r in applied:
        by_area[r["item"].area].append(r)
    for area in sorted(by_area):
        out.append(f"=== {area} ===")
        for r in sorted(by_area[area], key=lambda x: x["item"].name.lower()):
            via = ", ".join(_via(a) for a in r["includes"])
            flag = "  [subject to filter]" if r["filtered"] else ""
            out.append(f"  {r['item'].name}  ← via {via}{flag}")
        out.append("")
    if excluded:
        out.append("Blocked by an exclusion (assigned, but excluded for this subject):")
        for r in sorted(excluded, key=lambda x: (x["item"].area, x["item"].name.lower())):
            out.append(f"  [{r['item'].area}] {r['item'].name}")
    return "\n".join(out)


def _via(a) -> str:
    t = a.target
    if t.kind == "allUsers":
        return "All Users"
    if t.kind == "allDevices":
        return "All Devices"
    return t.group_name or t.group_id or "?"


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


# ---- HTML report ------------------------------------------------------
def render_html(items: List[ResourceItem], *, title: str = "Intune Assignments") -> str:
    """A self-contained, filterable HTML assignment report (no build step)."""
    rows = flatten_rows(items)
    total = len(items)
    assigned = sum(1 for it in items if it.assignments)
    edges = sum(len(it.assignments) for it in items)
    groups = len({
        a.target.group_id for it in items for a in it.assignments if a.target.group_id
    })
    data = json.dumps(rows)
    kpis = [
        ("Resources", total),
        ("Assigned", assigned),
        ("Unassigned", total - assigned),
        ("Assignment edges", edges),
        ("Distinct groups", groups),
    ]
    kpi_html = "".join(
        f'<div class="kpi"><div class="kpi-n">{v}</div>'
        f'<div class="kpi-l">{k}</div></div>'
        for k, v in kpis
    )
    return _HTML_TEMPLATE.replace("__TITLE__", _esc(title)) \
        .replace("__KPIS__", kpi_html) \
        .replace("__DATA__", data)


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


_HTML_TEMPLATE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
  :root{
    --bg:#0b1220; --panel:#121a2b; --panel2:#0f1726; --line:#22304b;
    --text:#e6edf7; --muted:#8a9ac0; --accent:#3b82f6;
    --inc:#1f9d55; --exc:#e0245e; --chip:#1b2a44;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
    font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
  header{padding:20px 24px;border-bottom:1px solid var(--line);
    background:linear-gradient(180deg,#101a2e,#0b1220)}
  h1{margin:0;font-size:18px;font-weight:650;letter-spacing:.2px}
  .sub{color:var(--muted);font-size:12px;margin-top:4px}
  .kpis{display:flex;gap:12px;flex-wrap:wrap;padding:16px 24px}
  .kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;
    padding:12px 16px;min-width:120px}
  .kpi-n{font-size:22px;font-weight:700}
  .kpi-l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
  .controls{display:flex;gap:10px;flex-wrap:wrap;padding:0 24px 16px;align-items:center}
  input,select{background:var(--panel2);border:1px solid var(--line);color:var(--text);
    border-radius:8px;padding:9px 12px;font-size:13px;outline:none}
  input:focus,select:focus{border-color:var(--accent)}
  input[type=search]{min-width:280px}
  .count{color:var(--muted);font-size:12px;margin-left:auto}
  .wrap{padding:0 24px 40px}
  table{width:100%;border-collapse:collapse;background:var(--panel);
    border:1px solid var(--line);border-radius:10px;overflow:hidden}
  th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line);
    vertical-align:top}
  th{position:sticky;top:0;background:var(--panel2);font-size:11px;
    text-transform:uppercase;letter-spacing:.6px;color:var(--muted);cursor:pointer}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#15203450}
  .chip{display:inline-block;background:var(--chip);border:1px solid var(--line);
    border-radius:999px;padding:2px 9px;font-size:11px;color:#cdd9ee}
  .tag-inc{color:#7ee2a8} .tag-exc{color:#ff89ab;font-weight:600}
  .tag-virtual{color:#ffd479}
  .muted{color:var(--muted)}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
  footer{padding:16px 24px;color:var(--muted);font-size:11px}
</style></head><body>
<header>
  <h1>__TITLE__</h1>
  <div class="sub">Generated by intuneassigner · static report, no live data</div>
</header>
<div class="kpis">__KPIS__</div>
<div class="controls">
  <input type="search" id="q" placeholder="Search resource, group, filter…">
  <select id="area"><option value="">All areas</option></select>
  <select id="mode">
    <option value="">Include &amp; exclude</option>
    <option value="include">Include only</option>
    <option value="exclude">Exclude only</option>
    <option value="unassigned">Unassigned</option>
  </select>
  <span class="count" id="count"></span>
</div>
<div class="wrap">
  <table id="t"><thead><tr>
    <th data-k="area">Area</th><th data-k="resource_name">Resource</th>
    <th data-k="platform">Platform</th><th data-k="target">Assigned to</th>
    <th data-k="intent">Intent</th><th data-k="filter">Filter</th>
  </tr></thead><tbody id="tb"></tbody></table>
</div>
<footer>intuneassigner — Microsoft Intune assignment report</footer>
<script>
const DATA = __DATA__;
const tb = document.getElementById('tb'), q = document.getElementById('q'),
      areaSel = document.getElementById('area'), modeSel = document.getElementById('mode'),
      countEl = document.getElementById('count');
[...new Set(DATA.map(r=>r.area))].sort().forEach(a=>{
  const o=document.createElement('option');o.value=a;o.textContent=a;areaSel.appendChild(o);});
let sortK='area', sortDir=1;
function esc(s){return (s==null?'':''+s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function modeOf(r){
  if(r.target==='(unassigned)')return 'unassigned';
  return r.exclude?'exclude':(r.target_kind==='group'?'include':r.target_kind);}
function render(){
  const term=q.value.toLowerCase(), area=areaSel.value, mode=modeSel.value;
  let rows=DATA.filter(r=>{
    if(area && r.area!==area)return false;
    if(mode==='unassigned' && r.target!=='(unassigned)')return false;
    if(mode==='include' && !(r.target!=='(unassigned)' && !r.exclude))return false;
    if(mode==='exclude' && !r.exclude)return false;
    if(!term)return true;
    return [r.resource_name,r.group_name,r.target,r.filter,r.area].join(' ').toLowerCase().includes(term);
  });
  rows.sort((a,b)=>((''+a[sortK]).localeCompare(''+b[sortK]))*sortDir);
  tb.innerHTML=rows.map(r=>{
    let tcls = r.exclude?'tag-exc':(['allUsers','allDevices'].includes(r.target_kind)?'tag-virtual':'tag-inc');
    let tgt = r.target==='(unassigned)'?'<span class="muted">unassigned</span>':`<span class="${tcls}">${esc(r.target)}</span>`;
    return `<tr><td><span class="chip">${esc(r.area)}</span></td>
      <td>${esc(r.resource_name)}</td><td class="muted">${esc(r.platform)}</td>
      <td>${tgt}</td><td>${esc(r.intent)}</td>
      <td class="muted">${esc(r.filter)}${r.filter?` <span class="muted">(${esc(r.filter_type)})</span>`:''}</td></tr>`;
  }).join('');
  countEl.textContent=`${rows.length} row(s)`;
}
document.querySelectorAll('th').forEach(th=>th.onclick=()=>{
  const k=th.dataset.k; sortDir=(k===sortK)?-sortDir:1; sortK=k; render();});
q.oninput=areaSel.onchange=modeSel.onchange=render;
render();
</script>
</body></html>"""
