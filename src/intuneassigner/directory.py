"""Resolve group and assignment-filter IDs to human names — and back.

This is what makes assignments *readable*: Graph returns bare GUIDs on every
target, so the directory caches id↔name maps for security groups and Intune
assignment filters. Lookups are batched and memoised so enumerating a whole
tenant resolves every group with a handful of calls.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from .graph import GraphClient, GRAPH_V1
from .models import GroupRef


class Directory:
    def __init__(self, client: GraphClient) -> None:
        self.client = client
        self._groups: Dict[str, GroupRef] = {}
        self._by_name: Dict[str, List[GroupRef]] = {}
        self._filters: Dict[str, str] = {}
        self._filters_loaded = False

    # ---- assignment filters ------------------------------------------
    def load_filters(self) -> None:
        if self._filters_loaded:
            return
        items = self.client.get_all(
            "deviceManagement/assignmentFilters?$select=id,displayName"
        )
        for it in items:
            self._filters[it.get("id", "")] = it.get("displayName", "")
        self._filters_loaded = True

    def filter_name(self, filter_id: Optional[str]) -> Optional[str]:
        if not filter_id:
            return None
        if not self._filters_loaded:
            self.load_filters()
        return self._filters.get(filter_id)

    def filter_id_by_name(self, name: Optional[str]) -> Optional[str]:
        if not name:
            return None
        if not self._filters_loaded:
            self.load_filters()
        for fid, fname in self._filters.items():
            if fname.lower() == name.lower():
                return fid
        return None

    # ---- groups -------------------------------------------------------
    def resolve_ids(self, group_ids: Iterable[str]) -> None:
        """Bulk-resolve group ids to names via $batch, caching results."""
        unknown = [g for g in {gid for gid in group_ids if gid} if g not in self._groups]
        if not unknown:
            return
        reqs = [
            {
                "id": str(i),
                "method": "GET",
                "url": f"/groups/{gid}?$select=id,displayName,description,"
                "securityEnabled,membershipRule",
            }
            for i, gid in enumerate(unknown)
        ]
        # Group reads live on v1.0; use a v1.0 client view for the batch root.
        v1 = GraphClient(self.client._token, base=GRAPH_V1, transport=self.client.transport)
        for resp in v1.batch(reqs):
            idx = int(resp.get("id"))
            gid = unknown[idx]
            if resp.get("status") == 200 and isinstance(resp.get("body"), dict):
                ref = GroupRef.from_graph(resp["body"])
                self._cache_group(ref)
            else:
                # Deleted or inaccessible group — record the GUID so reports show
                # an "(orphaned)" marker instead of silently dropping it.
                self._cache_group(GroupRef(id=gid, display_name=f"(unresolved {gid[:8]}…)"))

    def name(self, group_id: Optional[str]) -> Optional[str]:
        if not group_id:
            return None
        ref = self._groups.get(group_id)
        if ref is None:
            self.resolve_ids([group_id])
            ref = self._groups.get(group_id)
        return ref.display_name if ref else group_id

    def group(self, group_id: str) -> Optional[GroupRef]:
        if group_id not in self._groups:
            self.resolve_ids([group_id])
        return self._groups.get(group_id)

    def find_by_name(self, name: str) -> List[GroupRef]:
        """Look up a group by exact display name (Graph-side $filter)."""
        key = name.lower()
        if key in self._by_name:
            return self._by_name[key]
        esc = name.replace("'", "''")
        items = self.client.get_all(
            f"groups?$filter=displayName eq '{esc}'"
            "&$select=id,displayName,description,securityEnabled,membershipRule"
        )
        refs = [GroupRef.from_graph(it) for it in items]
        for r in refs:
            self._cache_group(r)
        self._by_name[key] = refs
        return refs

    def resolve_group_arg(self, value: str) -> GroupRef:
        """Resolve a CLI group argument that may be a GUID or a display name."""
        if _looks_like_guid(value):
            ref = self.group(value)
            if ref:
                return ref
        matches = self.find_by_name(value)
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise ValueError(f"No group found matching '{value}'.")
        names = ", ".join(f"{m.display_name} ({m.id})" for m in matches)
        raise ValueError(f"'{value}' is ambiguous — matches: {names}")

    def _cache_group(self, ref: GroupRef) -> None:
        self._groups[ref.id] = ref
        self._by_name.setdefault(ref.display_name.lower(), [])
        if ref not in self._by_name[ref.display_name.lower()]:
            existing = {g.id for g in self._by_name[ref.display_name.lower()]}
            if ref.id not in existing:
                self._by_name[ref.display_name.lower()].append(ref)


def _looks_like_guid(value: str) -> bool:
    parts = value.split("-")
    return len(parts) == 5 and len(value.replace("-", "")) == 32
