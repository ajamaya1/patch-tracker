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


def _esc(s) -> str:
    import html
    return html.escape("" if s is None else str(s))


def render_html_report(payload: dict) -> str:
    """Render a standalone HTML report from a :func:`site.build_payload` dict.

    Includes per-patch remediation (with Windows client/server sections) and a
    CVE table -- the same information the dashboard shows, as a self-contained
    file suitable for emailing or archiving.
    """
    s = payload.get("stats", {})
    parts = [_HTML_HEAD]
    parts.append(
        f"<h1>🛡️ Patch Tracker report</h1>"
        f"<div class='meta'>Data updated {_esc(payload.get('generated_at'))}"
        f" &middot; {s.get('total_patches', 0)} patches"
        f" &middot; {s.get('total_cves', 0)} CVEs"
        f" &middot; {s.get('exploited_cves', 0)} exploited"
        f" &middot; {s.get('new_cves', 0)} new</div>"
    )
    for p in payload.get("patches", []):
        parts.append(_html_patch(p))
    parts.append("</body></html>")
    return "".join(parts)


def _html_patch(p: dict) -> str:
    badges = [p.get("source"), p.get("platform"), p.get("severity")]
    sub = " &middot; ".join(_esc(b) for b in badges if b)
    extra = []
    if p.get("patch_tuesday"):
        extra.append("Patch Tuesday " + _esc(p["patch_tuesday"]))
    sv = p.get("servicing") or {}
    if sv:
        hp = sv.get("hotpatch", {})
        extra.append(_esc(sv.get("channel_label")))
        extra.append(_esc(hp.get("update_type")))
    aff = p.get("affected") or {}
    if aff.get("client") or aff.get("server"):
        extra.append(f"client:{aff.get('client',0)} server:{aff.get('server',0)}")
    extra_html = (" <small>" + " &middot; ".join(extra) + "</small>") if extra else ""

    out = [f"<h2>{_esc(p.get('title'))} <small>{sub}</small>{extra_html}</h2>"]

    rem = p.get("remediation") or {}
    if rem:
        out.append(f"<div class='rem rem-{_esc(rem.get('urgency','normal'))}'>")
        out.append(f"<p class='rem-note'><b>{_esc(rem.get('urgency','').upper())}"
                   f"</b> — {_esc(rem.get('note'))}</p>")
        out.append(f"<p>{_esc(rem.get('summary'))}</p>")
        for sec in rem.get("sections", []):
            out.append(f"<p class='aud'>{_esc(sec.get('icon',''))} "
                       f"<b>{_esc(sec.get('audience'))}</b></p><ul>")
            for step in sec.get("steps", []):
                out.append(f"<li>{_esc(step)}</li>")
            out.append("</ul>")
        if rem.get("links"):
            links = " &middot; ".join(
                f"<a href='{_esc(l['url'])}'>{_esc(l['label'])}</a>"
                for l in rem["links"])
            out.append(f"<p class='links'>{links}</p>")
        out.append("</div>")

    out.append("<table><thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th>"
               "<th>Impact</th><th>Exploited</th><th>New</th>"
               "<th>Affected</th></tr></thead><tbody>")
    for c in p.get("cves", []):
        cls = " class='x'" if c.get("exploited") else ""
        out.append(
            f"<tr{cls}><td>{_esc(c.get('cve_id'))}</td>"
            f"<td>{_esc(c.get('severity') or '—')}</td>"
            f"<td>{_esc(c.get('base_score') if c.get('base_score') is not None else '—')}</td>"
            f"<td>{_esc(c.get('impact') or '—')}</td>"
            f"<td>{'yes' if c.get('exploited') else ''}</td>"
            f"<td>{'new' if c.get('is_new') else ''}</td>"
            f"<td>{_esc(', '.join(c.get('product_kinds') or []) or '—')}</td></tr>"
        )
    out.append("</tbody></table>")
    return "".join(out)


_HTML_HEAD = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Patch Tracker report</title><style>
body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px;color:#16202c}
h1{margin:0 0 4px} .meta{color:#667;margin-bottom:18px;font-size:14px}
h2{margin:24px 0 6px;font-size:17px;border-bottom:2px solid #e3e8ee;padding-bottom:4px}
h2 small{font-weight:400;color:#789;font-size:12px}
.rem{border-left:4px solid #888;background:#f7f9fb;padding:8px 12px;margin:8px 0;border-radius:4px;font-size:13px}
.rem-critical{border-color:#d23;background:#fdecec}
.rem-high{border-color:#e8910c;background:#fff6e8}
.rem .aud{margin:6px 0 2px} .rem ul{margin:2px 0 8px 18px} .rem-note{margin:0 0 6px}
.links a{margin-right:6px}
table{border-collapse:collapse;width:100%;font-size:13px;margin-bottom:8px}
th,td{border:1px solid #dce3ea;padding:5px 8px;text-align:left}
th{background:#f3f6f9} tr.x{background:#fdecec}
</style></head><body>"""
