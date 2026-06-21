"""Command-line interface for the security patch tracker.

Subcommands::

    fetch    Pull the latest data from SOFA (Apple) and/or MSRC (Microsoft)
    list     List tracked patches with their triage status
    show     Show a single patch and the CVEs it fixes
    cves     List/search individual CVEs (e.g. only actively-exploited ones)
    status   Set the tracking status of a patch (applied / in_progress / ...)
    stats    Print a summary dashboard
    export   Dump patches+CVEs to JSON or CSV
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import io
import json
import sys
from typing import List, Optional

from . import __version__
from .db import DEFAULT_DB_PATH, Database
from .fetcher import FetchError, http_get_json, load_json_file
from .models import TRACKING_STATUSES
from .report import render_table, short_date
from .sources import apple_sofa, microsoft_msrc


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------
def cmd_fetch(args: argparse.Namespace, db: Database) -> int:
    fetched_at = _now()
    patches = []

    # Offline ingest: parse a previously-saved feed file instead of the network.
    if args.file:
        if not args.source or args.source == "all":
            print(
                "error: --file requires --source apple or --source microsoft",
                file=sys.stderr,
            )
            return 2
        data = load_json_file(args.file)
        if args.source == "apple":
            patches = apple_sofa.parse_feed(data, fetched_at)
        else:
            # A single CVRF document; synthesize a minimal summary from it.
            summary = _summary_from_cvrf(data)
            patches = [microsoft_msrc.parse_cvrf(summary, data, fetched_at)]
        n = db.upsert_patches(patches)
        print(f"Ingested {n} patch(es) ({len(_all_cves(patches))} CVEs) "
              f"from {args.file}")
        return 0

    sources = (
        ["apple", "microsoft"] if args.source in (None, "all") else [args.source]
    )
    platforms = ["macos"]
    if args.ios:
        platforms.append("ios")

    try:
        if "apple" in sources:
            apple_patches = apple_sofa.fetch(
                http_get_json, fetched_at, platforms=tuple(platforms)
            )
            patches.extend(apple_patches)
            print(f"Apple (SOFA): {len(apple_patches)} security release(s)")
        if "microsoft" in sources:
            ms_patches = microsoft_msrc.fetch(
                http_get_json, fetched_at, months=args.months
            )
            patches.extend(ms_patches)
            print(f"Microsoft (MSRC): {len(ms_patches)} monthly update(s)")
    except FetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    n = db.upsert_patches(patches)
    print(f"Stored {n} patch(es), {len(_all_cves(patches))} CVE links.")
    return 0


def _summary_from_cvrf(doc: dict) -> dict:
    title_obj = doc.get("DocumentTitle") or {}
    title = title_obj.get("Value") if isinstance(title_obj, dict) else str(title_obj)
    tracking = doc.get("DocumentTracking") or {}
    ident = (tracking.get("Identification") or {}).get("ID") or {}
    update_id = ident.get("Value") if isinstance(ident, dict) else None
    update_id = update_id or title or "msrc-import"
    cur = (tracking.get("CurrentReleaseDate"))
    return {
        "id": update_id,
        "title": title or update_id,
        "release_date": cur,
        "url": microsoft_msrc.cvrf_url(update_id),
    }


def _all_cves(patches) -> list:
    out = []
    for p in patches:
        out.extend(p.cves)
    return out


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------
def cmd_list(args: argparse.Namespace, db: Database) -> int:
    rows = db.list_patches(
        source=args.source,
        status=args.status,
        severity=args.severity,
        exploited_only=args.exploited,
        since=args.since,
        limit=args.limit,
    )
    if args.json:
        print(json.dumps([dict(r) for r in rows], indent=2, default=str))
        return 0
    table = render_table(
        ["PATCH ID", "REL DATE", "SEV", "CVEs", "EXPL", "STATUS", "TITLE"],
        [
            [
                r["patch_id"],
                short_date(r["release_date"]),
                r["severity"] or "-",
                r["cve_count"],
                r["exploited_count"] or "-",
                r["status"] or "-",
                r["title"],
            ]
            for r in rows
        ],
    )
    print(table)
    return 0


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------
def cmd_show(args: argparse.Namespace, db: Database) -> int:
    patch = db.get_patch(args.patch_id)
    if patch is None:
        print(f"error: no patch with id {args.patch_id!r}", file=sys.stderr)
        return 1
    cves = db.get_cves_for_patch(args.patch_id)
    if args.json:
        print(json.dumps(
            {"patch": dict(patch), "cves": [dict(c) for c in cves]},
            indent=2, default=str,
        ))
        return 0

    print(f"Patch:     {patch['patch_id']}")
    print(f"Title:     {patch['title']}")
    print(f"Source:    {patch['source']}")
    print(f"Product:   {patch['product'] or '-'}  (version {patch['version'] or '-'})")
    print(f"Released:  {short_date(patch['release_date']) or '-'}")
    print(f"Severity:  {patch['severity'] or '-'}")
    print(f"Status:    {patch['status'] or '-'}")
    if patch["note"]:
        print(f"Note:      {patch['note']}")
    if patch["url"]:
        print(f"URL:       {patch['url']}")
    print(f"CVEs:      {len(cves)}")
    print()
    print(render_table(
        ["CVE", "SEV", "SCORE", "EXPL", "DISC", "IMPACT"],
        [
            [
                c["cve_id"],
                c["severity"] or "-",
                c["base_score"] if c["base_score"] is not None else "-",
                "yes" if c["exploited"] else "-",
                "yes" if c["publicly_disclosed"] else "-",
                c["impact"] or "-",
            ]
            for c in cves
        ],
    ))
    return 0


# ---------------------------------------------------------------------------
# cves
# ---------------------------------------------------------------------------
def cmd_cves(args: argparse.Namespace, db: Database) -> int:
    rows = db.list_cves(
        cve_id=args.cve,
        severity=args.severity,
        exploited_only=args.exploited,
        source=args.source,
        since=args.since,
        limit=args.limit,
    )
    if args.json:
        print(json.dumps([dict(r) for r in rows], indent=2, default=str))
        return 0
    print(render_table(
        ["CVE", "SEV", "SCORE", "EXPL", "SOURCE", "REL DATE", "PATCH"],
        [
            [
                r["cve_id"],
                r["severity"] or "-",
                r["base_score"] if r["base_score"] is not None else "-",
                "yes" if r["exploited"] else "-",
                r["source"],
                short_date(r["release_date"]),
                r["patch_title"],
            ]
            for r in rows
        ],
    ))
    return 0


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------
def cmd_status(args: argparse.Namespace, db: Database) -> int:
    if args.new_status not in TRACKING_STATUSES:
        print(
            f"error: invalid status {args.new_status!r}. "
            f"Choose from: {', '.join(TRACKING_STATUSES)}",
            file=sys.stderr,
        )
        return 2
    ok = db.set_status(args.patch_id, args.new_status, args.note, _now())
    if not ok:
        print(f"error: no patch with id {args.patch_id!r}", file=sys.stderr)
        return 1
    print(f"{args.patch_id} -> {args.new_status}")
    return 0


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------
def cmd_stats(args: argparse.Namespace, db: Database) -> int:
    s = db.stats()
    if args.json:
        print(json.dumps(s, indent=2))
        return 0
    print("Patch Tracker summary")
    print("=====================")
    print(f"Patches:         {s['total_patches']}")
    print(f"Unique CVEs:     {s['total_cves']}")
    print(f"Exploited CVEs:  {s['exploited_cves']}")
    print()
    print("By source:   " + _kv(s["by_source"]))
    print("By severity: " + _kv(s["by_severity"]))
    print("By status:   " + _kv(s["by_status"]))
    return 0


def _kv(d: dict) -> str:
    if not d:
        return "(none)"
    return ", ".join(f"{k}={v}" for k, v in sorted(d.items()))


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------
def cmd_export(args: argparse.Namespace, db: Database) -> int:
    patch_rows = db.list_patches()
    payload = []
    for p in patch_rows:
        cves = db.get_cves_for_patch(p["patch_id"])
        rec = dict(p)
        rec["cves"] = [dict(c) for c in cves]
        payload.append(rec)

    if args.format == "json":
        out = json.dumps(payload, indent=2, default=str)
    else:  # csv -- one row per CVE, flattened with its patch context
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "patch_id", "source", "patch_title", "release_date",
            "patch_severity", "status", "cve_id", "cve_severity",
            "base_score", "exploited", "publicly_disclosed", "impact",
        ])
        for p in payload:
            if not p["cves"]:
                writer.writerow([
                    p["patch_id"], p["source"], p["title"],
                    short_date(p["release_date"]), p["severity"],
                    p["status"], "", "", "", "", "", "",
                ])
            for c in p["cves"]:
                writer.writerow([
                    p["patch_id"], p["source"], p["title"],
                    short_date(p["release_date"]), p["severity"], p["status"],
                    c["cve_id"], c["severity"], c["base_score"],
                    c["exploited"], c["publicly_disclosed"], c["impact"],
                ])
        out = buf.getvalue()

    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="") as fh:
            fh.write(out)
        print(f"Wrote {len(payload)} patch records to {args.out}")
    else:
        sys.stdout.write(out)
        if not out.endswith("\n"):
            sys.stdout.write("\n")
    return 0


# ---------------------------------------------------------------------------
# argument parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="patch-tracker",
        description="Track Apple (SOFA) and Microsoft (MSRC) security patches "
                    "and your remediation status for them.",
    )
    parser.add_argument("--version", action="version",
                        version=f"patch-tracker {__version__}")
    parser.add_argument("--db", default=DEFAULT_DB_PATH,
                        help=f"SQLite database path (default: {DEFAULT_DB_PATH})")
    sub = parser.add_subparsers(dest="command", required=True)

    p_fetch = sub.add_parser("fetch", help="Fetch latest security feeds")
    p_fetch.add_argument("--source", choices=["apple", "microsoft", "all"],
                         default="all")
    p_fetch.add_argument("--months", type=int, default=3,
                         help="How many recent MSRC monthly updates to pull")
    p_fetch.add_argument("--ios", action="store_true",
                         help="Also fetch the Apple iOS feed")
    p_fetch.add_argument("--file",
                         help="Ingest a saved feed JSON file instead of the "
                              "network (requires --source)")
    p_fetch.set_defaults(func=cmd_fetch)

    p_list = sub.add_parser("list", help="List tracked patches")
    p_list.add_argument("--source", choices=["apple", "microsoft"])
    p_list.add_argument("--status", choices=list(TRACKING_STATUSES))
    p_list.add_argument("--severity")
    p_list.add_argument("--exploited", action="store_true",
                        help="Only patches that fix an exploited CVE")
    p_list.add_argument("--since", help="Released on/after this ISO date")
    p_list.add_argument("--limit", type=int)
    p_list.add_argument("--json", action="store_true")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", help="Show a patch and its CVEs")
    p_show.add_argument("patch_id")
    p_show.add_argument("--json", action="store_true")
    p_show.set_defaults(func=cmd_show)

    p_cves = sub.add_parser("cves", help="List/search CVEs")
    p_cves.add_argument("--cve", help="Look up a specific CVE id")
    p_cves.add_argument("--severity")
    p_cves.add_argument("--exploited", action="store_true")
    p_cves.add_argument("--source", choices=["apple", "microsoft"])
    p_cves.add_argument("--since")
    p_cves.add_argument("--limit", type=int)
    p_cves.add_argument("--json", action="store_true")
    p_cves.set_defaults(func=cmd_cves)

    p_status = sub.add_parser("status", help="Set a patch's tracking status")
    p_status.add_argument("patch_id")
    p_status.add_argument("new_status",
                          help="One of: " + ", ".join(TRACKING_STATUSES))
    p_status.add_argument("--note")
    p_status.set_defaults(func=cmd_status)

    p_stats = sub.add_parser("stats", help="Print a summary dashboard")
    p_stats.add_argument("--json", action="store_true")
    p_stats.set_defaults(func=cmd_stats)

    p_export = sub.add_parser("export", help="Export patches+CVEs")
    p_export.add_argument("--format", choices=["json", "csv"], default="json")
    p_export.add_argument("--out", help="Output file (default: stdout)")
    p_export.set_defaults(func=cmd_export)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    with Database(args.db) as db:
        return args.func(args, db)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
