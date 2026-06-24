"""Command-line interface for intuneassigner.

    intuneassigner areas                       # what can be inspected
    intuneassigner list --area Apps            # all assignments, groups resolved
    intuneassigner group "All Workstations"    # reverse lookup
    intuneassigner copy --from GRP_A --to GRP_B
    intuneassigner bulk-assign --group GRP --area Compliance
    intuneassigner template export --group GRP --name baseline --out baseline.json
    intuneassigner template apply --file baseline.json --group NEW_GRP
    intuneassigner audit --out audit.txt

Auth is read from the environment by default (``INTUNE_TENANT``,
``INTUNEASSIGNER_CLIENT_ID``, ``INTUNE_CLIENT_SECRET``) or supplied with flags.
Already have a bearer token (e.g. ``az account get-access-token``)? Pass
``--token`` / set ``INTUNE_TOKEN`` and skip interactive sign-in entirely.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .assignments import AssignmentEngine
from .auth import Authenticator
from .directory import Directory
from .errors import IntuneToolError
from .graph import GRAPH_BETA, GraphClient
from .resources import AREAS, REGISTRY, resolve_types
from . import report
from .templates import Template


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


# ---- engine wiring ----------------------------------------------------
def build_engine(args) -> AssignmentEngine:
    token = args.token or os.environ.get("INTUNE_TOKEN")
    if token:
        token_provider = lambda: token  # noqa: E731
    else:
        auth = Authenticator.from_env()
        if args.tenant:
            auth.tenant = args.tenant
        if args.client_id:
            auth.client_id = args.client_id
        if args.client_secret:
            auth.client_secret = args.client_secret
            auth.flow = "client_credentials"
        token_provider = auth.token
    client = GraphClient(token_provider, base=args.graph_base)
    engine = AssignmentEngine(
        client, Directory(client), on_progress=(_eprint if args.verbose else None)
    )
    return engine


def _enumerate(engine: AssignmentEngine, args, *, only_assigned=False):
    keys = args.type or None
    areas = args.area or None
    return engine.enumerate(keys=keys, areas=areas, only_assigned=only_assigned)


def _resolve_group(engine: AssignmentEngine, value: str):
    return engine.dir.resolve_group_arg(value)


# ---- command handlers -------------------------------------------------
def cmd_areas(args) -> int:
    print("Areas and resource types intuneassigner can inspect:\n")
    last = None
    for rt in sorted(REGISTRY, key=lambda r: (r.area, r.label)):
        if rt.area != last:
            print(f"\n{rt.area}:")
            last = rt.area
        print(f"  {rt.key:<34} {rt.label}")
    print(f"\n{len(REGISTRY)} resource types across {len(AREAS)} areas.")
    return 0


def cmd_list(args) -> int:
    engine = build_engine(args)
    items = _enumerate(engine, args, only_assigned=args.assigned_only)
    if args.platform:
        pl = args.platform.lower()
        items = [it for it in items if (it.platform or "").lower().find(pl) >= 0]
    _emit(items, args)
    return 0


def cmd_group(args) -> int:
    engine = build_engine(args)
    ref = _resolve_group(engine, args.group)
    items = _enumerate(engine, args, only_assigned=True)
    hits = engine.by_group(ref.id, items)
    if args.output == "json":
        sub = [it for it, _ in hits]
        print(report.to_json(sub))
    elif args.output == "csv":
        sub = [it for it, _ in hits]
        _write(args, report.to_csv(sub))
    else:
        print(report.render_group_report(ref.display_name, ref.id, hits))
    return 0


def cmd_copy(args) -> int:
    engine = build_engine(args)
    src = _resolve_group(engine, getattr(args, "from"))
    dst = _resolve_group(engine, args.to)
    items = _enumerate(engine, args, only_assigned=True)
    plans = engine.copy_group(
        src.id, dst.id, items, dry_run=args.dry_run, include_filters=not args.no_filters
    )
    print(f"Copying assignments: {src.display_name} → {dst.display_name}")
    print(report.render_change_plans(plans, dry_run=args.dry_run))
    return 0


def cmd_bulk_assign(args) -> int:
    engine = build_engine(args)
    ref = _resolve_group(engine, args.group)
    items = _enumerate(engine, args)
    if args.name_contains:
        needle = args.name_contains.lower()
        items = [it for it in items if needle in it.name.lower()]
    filter_id = engine.dir.filter_id_by_name(args.filter) if args.filter else None
    plans = engine.bulk_assign(
        ref.id, items,
        exclude=args.exclude, intent=args.intent,
        filter_id=filter_id, filter_type=args.filter_type,
        dry_run=args.dry_run,
    )
    mode = "EXCLUDE" if args.exclude else "include"
    print(f"Bulk-assigning {ref.display_name} ({mode}) to {len(items)} resource(s)")
    print(report.render_change_plans(plans, dry_run=args.dry_run))
    return 0


def cmd_audit(args) -> int:
    engine = build_engine(args)
    items = _enumerate(engine, args)
    text = report.render_audit(items)
    _write(args, text)
    if args.out:
        _eprint(f"Audit written to {args.out}")
    return 0


def cmd_template_export(args) -> int:
    engine = build_engine(args)
    ref = _resolve_group(engine, args.group)
    items = _enumerate(engine, args, only_assigned=True)
    tmpl = engine.template_from_group(
        ref.id, items, name=args.name, description=args.description or ""
    )
    if args.out:
        tmpl.save(args.out)
        _eprint(f"Template '{tmpl.name}' with {len(tmpl.resources)} resource(s) → {args.out}")
    else:
        import json
        print(json.dumps(tmpl.to_dict(), indent=2))
    return 0


def cmd_template_apply(args) -> int:
    engine = build_engine(args)
    tmpl = Template.load(args.file)
    ref = _resolve_group(engine, args.group)
    keys = sorted({r.resource_type for r in tmpl.resources})
    items = engine.enumerate(keys=keys)
    plans = engine.apply_template(tmpl, ref.id, items, dry_run=args.dry_run)
    print(f"Applying template '{tmpl.name}' to {ref.display_name}")
    print(report.render_change_plans(plans, dry_run=args.dry_run))
    return 0


def cmd_template_show(args) -> int:
    tmpl = Template.load(args.file)
    print(f"Template: {tmpl.name}")
    if tmpl.description:
        print(f"  {tmpl.description}")
    print(f"  {len(tmpl.resources)} resource(s):\n")
    for area, resources in sorted(tmpl.by_area().items()):
        print(f"  {area}:")
        for r in resources:
            extra = []
            if r.intent:
                extra.append(r.intent)
            if r.exclude:
                extra.append("EXCLUDE")
            if r.filter_name:
                extra.append(f"filter {r.filter_type}:{r.filter_name}")
            suffix = f"  ({', '.join(extra)})" if extra else ""
            print(f"    - {r.name}{suffix}")
    return 0


# ---- output helpers ---------------------------------------------------
def _emit(items, args) -> None:
    if args.output == "json":
        _write(args, report.to_json(items))
    elif args.output == "csv":
        _write(args, report.to_csv(items))
    else:
        text = report.render_assignments_table(items)
        _write(args, text)


def _write(args, text: str) -> None:
    if getattr(args, "out", None):
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
    else:
        print(text)


# ---- argparse ---------------------------------------------------------
def _add_auth(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("auth")
    g.add_argument("--tenant", help="Tenant id or domain (or INTUNE_TENANT)")
    g.add_argument("--client-id", help="App/client id (or INTUNEASSIGNER_CLIENT_ID)")
    g.add_argument("--client-secret", help="App secret → client-credentials flow (or INTUNE_CLIENT_SECRET)")
    g.add_argument("--token", help="Use an existing bearer token; skip sign-in (or INTUNE_TOKEN)")
    g.add_argument("--graph-base", default=GRAPH_BETA, help="Graph base URL (default: beta)")


def _add_scope(p: argparse.ArgumentParser) -> None:
    p.add_argument("--area", action="append", help="Limit to area(s); repeatable")
    p.add_argument("--type", action="append", help="Limit to resource type key(s); repeatable")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="intuneassigner", description=__doc__)
    p.add_argument("--version", action="version", version=f"intuneassigner {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="Progress to stderr")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("areas", help="List inspectable areas/resource types")
    sp.set_defaults(func=cmd_areas)

    sp = sub.add_parser("list", help="List all assignments with resolved groups")
    _add_auth(sp); _add_scope(sp)
    sp.add_argument("--assigned-only", action="store_true", help="Hide unassigned resources")
    sp.add_argument("--platform", help="Filter by platform substring (windows/ios/…) ")
    sp.add_argument("--output", choices=["table", "json", "csv"], default="table")
    sp.add_argument("--out", help="Write to file instead of stdout")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("group", help="Reverse lookup: what is a group assigned to")
    _add_auth(sp); _add_scope(sp)
    sp.add_argument("group", help="Group display name or id")
    sp.add_argument("--output", choices=["table", "json", "csv"], default="table")
    sp.add_argument("--out", help="Write to file instead of stdout")
    sp.set_defaults(func=cmd_group)

    sp = sub.add_parser("copy", help="Copy all assignments from one group to another")
    _add_auth(sp); _add_scope(sp)
    sp.add_argument("--from", required=True, help="Source group (name or id)")
    sp.add_argument("--to", required=True, help="Destination group (name or id)")
    sp.add_argument("--no-filters", action="store_true", help="Don't copy assignment filters")
    sp.add_argument("--dry-run", action="store_true", help="Preview without writing")
    sp.set_defaults(func=cmd_copy)

    sp = sub.add_parser("bulk-assign", help="Assign one group to many resources")
    _add_auth(sp); _add_scope(sp)
    sp.add_argument("--group", required=True, help="Group to assign (name or id)")
    sp.add_argument("--name-contains", help="Only resources whose name contains this")
    sp.add_argument("--exclude", action="store_true", help="Add as an exclusion target")
    sp.add_argument("--intent", help="App install intent (required/available/uninstall/…) ")
    sp.add_argument("--filter", help="Assignment filter display name")
    sp.add_argument("--filter-type", choices=["include", "exclude"], default="include")
    sp.add_argument("--dry-run", action="store_true", help="Preview without writing")
    sp.set_defaults(func=cmd_bulk_assign)

    sp = sub.add_parser("audit", help="Tenant-wide assignment audit report")
    _add_auth(sp); _add_scope(sp)
    sp.add_argument("--out", help="Write report to file")
    sp.set_defaults(func=cmd_audit)

    tp = sub.add_parser("template", help="Reusable assignment templates")
    tsub = tp.add_subparsers(dest="tcmd", required=True)

    spe = tsub.add_parser("export", help="Capture a group's assignments as a template")
    _add_auth(spe); _add_scope(spe)
    spe.add_argument("--group", required=True, help="Group to capture (name or id)")
    spe.add_argument("--name", required=True, help="Template name")
    spe.add_argument("--description", help="Template description")
    spe.add_argument("--out", help="Write template JSON to file")
    spe.set_defaults(func=cmd_template_export)

    spa = tsub.add_parser("apply", help="Stamp a device group onto a template's resources")
    _add_auth(spa)
    spa.add_argument("--file", required=True, help="Template JSON file")
    spa.add_argument("--group", required=True, help="Device group to add (name or id)")
    spa.add_argument("--dry-run", action="store_true", help="Preview without writing")
    spa.set_defaults(func=cmd_template_apply)

    sps = tsub.add_parser("show", help="Print a template's contents")
    sps.add_argument("--file", required=True, help="Template JSON file")
    sps.set_defaults(func=cmd_template_show)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Defaults for scope attrs on commands that don't define them.
    for attr in ("area", "type", "out", "token"):
        if not hasattr(args, attr):
            setattr(args, attr, None)
    try:
        return args.func(args)
    except IntuneToolError as exc:
        _eprint(f"error: {exc}")
        return 2
    except ValueError as exc:
        _eprint(f"error: {exc}")
        return 2
    except BrokenPipeError:  # pragma: no cover
        return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
