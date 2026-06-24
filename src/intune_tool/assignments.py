"""The assignment engine: read everything, then act on it.

Built on top of :class:`GraphClient` and :class:`Directory`, this module
implements the verbs the user asked for:

* **enumerate** every assignable resource across all areas, with groups,
  filters, include/exclude intent and per-assignment settings resolved;
* **by_group** — the reverse lookup ("what is this group assigned to?");
* **copy** every assignment from one group onto another;
* **bulk_assign** a group (include or exclude, with an optional filter) onto a
  selection of resources;
* **apply_template** / **template_from_group** for reusable assignment sets.

Every write goes through the resource's ``/assign`` action, which *replaces*
the whole assignment list — so we always read-merge-write and never clobber
existing targets. Writes can be previewed with ``dry_run=True``.
"""

from __future__ import annotations

import copy as _copy
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .directory import Directory
from .errors import GraphError
from .graph import GraphClient
from .models import (
    Assignment,
    AssignmentTarget,
    ResourceItem,
    TARGET_EXCLUSION,
    TARGET_GROUP,
)
from .resources import (
    REGISTRY_BY_KEY,
    ResourceType,
    platform_of,
    resolve_types,
)


@dataclass
class ChangePlan:
    """A pending or executed assignment write on one resource."""

    resource_type: str
    area: str
    resource_id: str
    resource_name: str
    added: List[str] = field(default_factory=list)  # human descriptions
    body: Dict[str, Any] = field(default_factory=dict)
    applied: bool = False
    error: Optional[str] = None
    skipped_reason: Optional[str] = None


class AssignmentEngine:
    def __init__(
        self,
        client: GraphClient,
        directory: Optional[Directory] = None,
        *,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.client = client
        self.dir = directory or Directory(client)
        self._progress = on_progress or (lambda _msg: None)

    # ================================================================
    # READ
    # ================================================================
    def enumerate(
        self,
        keys: Optional[List[str]] = None,
        areas: Optional[List[str]] = None,
        *,
        only_assigned: bool = False,
    ) -> List[ResourceItem]:
        """Enumerate assignable resources with fully-resolved assignments."""
        types = resolve_types(keys, areas)
        items: List[ResourceItem] = []
        for rt in types:
            self._progress(f"Reading {rt.label} ({rt.area})…")
            try:
                items.extend(self._load_type(rt))
            except GraphError as exc:
                # A 403/404 on one area (no licence / no RBAC) must not abort the
                # whole sweep — record it and continue.
                self._progress(f"  skipped {rt.key}: {exc}")
        self._resolve_names(items)
        if only_assigned:
            items = [it for it in items if it.assignments]
        return items

    def _load_type(self, rt: ResourceType) -> List[ResourceItem]:
        select = ",".join(dict.fromkeys(("id", rt.name_field, "@odata.type") + rt.select))
        path = f"{rt.list_path}?$select={select}"
        if rt.expand_assignments:
            path += "&$expand=assignments"
        raw_items = self.client.get_all(path)
        out: List[ResourceItem] = []
        for raw in raw_items:
            if rt.odata_type_contains and rt.odata_type_contains.lower() not in (
                raw.get("@odata.type", "").lower()
            ):
                continue
            assigns = raw.get("assignments")
            if assigns is None and not rt.expand_assignments:
                assigns = self.client.get_all(rt.assignments_path(raw["id"]))
            item = ResourceItem(
                resource_type=rt.key,
                area=rt.area,
                id=raw.get("id", ""),
                name=raw.get(rt.name_field) or raw.get("displayName") or "(unnamed)",
                platform=platform_of(raw, rt),
                odata_type=raw.get("@odata.type"),
                assignments=[Assignment.from_graph(a) for a in (assigns or [])],
                raw=raw,
            )
            out.append(item)
        return out

    def _resolve_names(self, items: List[ResourceItem]) -> None:
        gids = {
            a.target.group_id
            for it in items
            for a in it.assignments
            if a.target.group_id
        }
        self.dir.resolve_ids(gids)
        self.dir.load_filters()
        for it in items:
            for a in it.assignments:
                t = a.target
                if t.group_id:
                    t.group_name = self.dir.name(t.group_id)
                if t.filter_id:
                    t.filter_name = self.dir.filter_name(t.filter_id)

    # ================================================================
    # REVERSE LOOKUP
    # ================================================================
    def by_group(
        self, group_id: str, items: List[ResourceItem]
    ) -> List[tuple]:
        """Return ``(ResourceItem, [Assignment,...])`` for resources touching a group."""
        hits = []
        for it in items:
            matched = it.targets_group(group_id)
            if matched:
                hits.append((it, matched))
        return hits

    # ================================================================
    # WRITE helpers
    # ================================================================
    def _assign_body(self, rt: ResourceType, assignments: List[Assignment]) -> Dict[str, Any]:
        entries = []
        for a in assignments:
            entry = a.to_graph()
            if rt.assignment_odata_type and "@odata.type" not in entry:
                entry = {"@odata.type": rt.assignment_odata_type, **entry}
            entries.append(entry)
        return {rt.assign_body_key: entries}

    def _commit(self, rt: ResourceType, item: ResourceItem, merged: List[Assignment]) -> Dict[str, Any]:
        body = self._assign_body(rt, merged)
        self.client.post(rt.assign_path(item.id), body)
        return body

    @staticmethod
    def _target_for_group(
        group_id: str,
        *,
        exclude: bool = False,
        filter_id: Optional[str] = None,
        filter_type: str = "none",
    ) -> AssignmentTarget:
        return AssignmentTarget(
            kind=TARGET_EXCLUSION if exclude else TARGET_GROUP,
            group_id=group_id,
            filter_id=filter_id,
            filter_type=filter_type if filter_id else "none",
        )

    # ================================================================
    # COPY group -> group
    # ================================================================
    def copy_group(
        self,
        src_group_id: str,
        dst_group_id: str,
        items: List[ResourceItem],
        *,
        dry_run: bool = False,
        include_filters: bool = True,
    ) -> List[ChangePlan]:
        """Mirror every assignment of ``src`` onto ``dst``.

        For each resource where the source group is targeted, an equivalent
        target for the destination group is appended (preserving include/exclude
        intent, app install intent + settings, and optionally the filter). Items
        already targeting ``dst`` for that edge are left untouched.
        """
        plans: List[ChangePlan] = []
        dst_name = self.dir.name(dst_group_id) or dst_group_id
        for it in items:
            rt = REGISTRY_BY_KEY[it.resource_type]
            src_edges = it.targets_group(src_group_id)
            if not src_edges:
                continue
            merged = list(it.assignments)
            existing_keys = {a.target.match_key() for a in merged}
            added_desc: List[str] = []
            for edge in src_edges:
                new_target = _copy.deepcopy(edge.target)
                new_target.group_id = dst_group_id
                new_target.group_name = dst_name
                if not include_filters:
                    new_target.filter_id = None
                    new_target.filter_type = "none"
                if new_target.match_key() in existing_keys:
                    continue
                new_assign = Assignment(
                    target=new_target,
                    intent=edge.intent,
                    settings=_copy.deepcopy(edge.settings) if edge.settings else None,
                )
                merged.append(new_assign)
                existing_keys.add(new_target.match_key())
                added_desc.append(new_target.display() + (f" [{edge.intent}]" if edge.intent else ""))
            if not added_desc:
                continue
            plan = ChangePlan(
                resource_type=it.resource_type,
                area=it.area,
                resource_id=it.id,
                resource_name=it.name,
                added=added_desc,
            )
            self._execute(rt, it, merged, plan, dry_run)
            plans.append(plan)
        return plans

    # ================================================================
    # BULK ASSIGN one group -> many resources
    # ================================================================
    def bulk_assign(
        self,
        group_id: str,
        items: List[ResourceItem],
        *,
        exclude: bool = False,
        intent: Optional[str] = None,
        filter_id: Optional[str] = None,
        filter_type: str = "include",
        settings: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
    ) -> List[ChangePlan]:
        """Add ``group`` as a target on every resource in ``items``."""
        plans: List[ChangePlan] = []
        gname = self.dir.name(group_id) or group_id
        for it in items:
            rt = REGISTRY_BY_KEY[it.resource_type]
            target = self._target_for_group(
                group_id, exclude=exclude, filter_id=filter_id, filter_type=filter_type
            )
            target.group_name = gname
            existing_keys = {a.target.match_key() for a in it.assignments}
            if target.match_key() in existing_keys:
                plans.append(
                    ChangePlan(
                        it.resource_type, it.area, it.id, it.name,
                        skipped_reason="already assigned",
                    )
                )
                continue
            eff_intent = intent if (rt.has_intent and intent) else None
            new_assign = Assignment(target=target, intent=eff_intent, settings=settings)
            merged = list(it.assignments) + [new_assign]
            plan = ChangePlan(
                it.resource_type, it.area, it.id, it.name,
                added=[target.display() + (f" [{eff_intent}]" if eff_intent else "")],
            )
            self._execute(rt, it, merged, plan, dry_run)
            plans.append(plan)
        return plans

    def _execute(
        self,
        rt: ResourceType,
        item: ResourceItem,
        merged: List[Assignment],
        plan: ChangePlan,
        dry_run: bool,
    ) -> None:
        plan.body = self._assign_body(rt, merged)
        if dry_run:
            return
        try:
            self.client.post(rt.assign_path(item.id), plan.body)
            plan.applied = True
        except GraphError as exc:
            plan.error = str(exc)

    # ================================================================
    # TEMPLATES
    # ================================================================
    def template_from_group(
        self, group_id: str, items: List[ResourceItem], *, name: str, description: str = ""
    ):
        """Capture everything a group is assigned to as a reusable template."""
        from .templates import Template, TemplateResource

        resources: List = []
        for it, edges in self.by_group(group_id, items):
            for edge in edges:
                resources.append(
                    TemplateResource(
                        resource_type=it.resource_type,
                        name=it.name,
                        id=it.id,
                        intent=edge.intent,
                        exclude=edge.target.is_exclude,
                        filter_name=edge.target.filter_name,
                        filter_type=edge.target.filter_type
                        if edge.target.filter_id
                        else "include",
                    )
                )
        return Template(name=name, description=description, resources=resources)

    def apply_template(
        self,
        template,
        group_id: str,
        items: List[ResourceItem],
        *,
        dry_run: bool = False,
    ) -> List[ChangePlan]:
        """Stamp ``group`` onto every resource listed in ``template``."""
        by_id = {it.id: it for it in items}
        by_name = {(it.resource_type, it.name): it for it in items}
        gname = self.dir.name(group_id) or group_id
        plans: List[ChangePlan] = []
        for tr in template.resources:
            it = by_id.get(tr.id) if tr.id else None
            if it is None:
                it = by_name.get((tr.resource_type, tr.name))
            if it is None:
                plans.append(
                    ChangePlan(
                        tr.resource_type, REGISTRY_BY_KEY[tr.resource_type].area,
                        tr.id or "", tr.name,
                        skipped_reason="resource not found in tenant",
                    )
                )
                continue
            rt = REGISTRY_BY_KEY[it.resource_type]
            filter_id = self.dir.filter_id_by_name(tr.filter_name) if tr.filter_name else None
            target = self._target_for_group(
                group_id, exclude=tr.exclude, filter_id=filter_id, filter_type=tr.filter_type
            )
            target.group_name = gname
            if target.match_key() in {a.target.match_key() for a in it.assignments}:
                plans.append(
                    ChangePlan(it.resource_type, it.area, it.id, it.name,
                               skipped_reason="already assigned")
                )
                continue
            eff_intent = tr.intent if rt.has_intent else None
            merged = list(it.assignments) + [
                Assignment(target=target, intent=eff_intent)
            ]
            plan = ChangePlan(
                it.resource_type, it.area, it.id, it.name,
                added=[target.display() + (f" [{eff_intent}]" if eff_intent else "")],
            )
            self._execute(rt, it, merged, plan, dry_run)
            plans.append(plan)
        return plans
