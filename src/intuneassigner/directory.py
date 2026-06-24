"""Resolve group and assignment-filter IDs to human names — and back.

This is what makes assignments *readable*: Graph returns bare GUIDs on every
target, so the directory caches id↔name maps for security groups and Intune
assignment filters. Lookups are batched and memoised so enumerating a whole
tenant resolves every group with a handful of calls.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional
from urllib.parse import quote as _quote

from .graph import GraphClient, GRAPH_V1
from .models import GroupRef


class Directory:
    def __init__(self, client: GraphClient) -> None:
        self.client = client
        self._groups: Dict[str, GroupRef] = {}
        self._by_name: Dict[str, List[GroupRef]] = {}
        self._filters: Dict[str, str] = {}
        self._filters_loaded = False
        self._counts: Dict[str, int] = {}
        self._v1c: Optional[GraphClient] = None

    def _v1(self) -> GraphClient:
        # Users/groups/devices live on the v1.0 graph, not the Intune beta root.
        if self._v1c is None:
            self._v1c = GraphClient(
                self.client._token, base=GRAPH_V1, transport=self.client.transport
            )
        return self._v1c

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
        for resp in self._v1().batch(reqs):
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

    # ---- membership --------------------------------------------------
    def member_count(self, group_id: str) -> int:
        """Direct member count of a group (cached). Used for empty-group checks."""
        if group_id in self._counts:
            return self._counts[group_id]
        try:
            n = self._v1().count(f"groups/{group_id}/members/$count")
        except Exception:
            n = -1  # unknown (e.g. no permission) — don't flag as empty
        self._counts[group_id] = n
        return n

    def member_counts(self, group_ids: Iterable[str]) -> Dict[str, int]:
        return {gid: self.member_count(gid) for gid in {g for g in group_ids if g}}

    def subject_groups(self, kind: str, value: str):
        """Resolve a user or device to (display, set-of-group-ids).

        ``kind`` is ``user`` or ``device``. Uses ``transitiveMemberOf`` so
        nested group membership is included — the same set Intune evaluates
        group-target assignments against.
        """
        v1 = self._v1()
        if kind == "user":
            ident = value if _looks_like_guid(value) else value  # UPN works directly
            subj = v1.get(f"users/{_quote(ident)}?$select=id,displayName,userPrincipalName")
            display = subj.get("displayName") or subj.get("userPrincipalName") or value
            oid = subj["id"]
        elif kind == "device":
            oid, display = self._resolve_device(value)
        else:
            raise ValueError(f"Unknown subject kind: {kind}")
        groups = v1.get_all(
            f"{'users' if kind == 'user' else 'devices'}/{oid}"
            "/transitiveMemberOf/microsoft.graph.group?$select=id,displayName"
        )
        gids = set()
        for g in groups:
            ref = GroupRef.from_graph(g)
            self._cache_group(ref)
            gids.add(ref.id)
        return display, gids

    def _resolve_device(self, value: str):
        v1 = self._v1()
        if _looks_like_guid(value):
            # Could be the Entra object id already, or an Intune device id.
            try:
                d = v1.get(f"devices/{value}?$select=id,displayName")
                return d["id"], d.get("displayName", value)
            except Exception:
                pass
        # By display name in Entra ID.
        esc = value.replace("'", "''")
        matches = v1.get_all(
            f"devices?$filter=displayName eq '{esc}'&$select=id,displayName,deviceId"
        )
        if len(matches) == 1:
            return matches[0]["id"], matches[0].get("displayName", value)
        if not matches:
            raise ValueError(f"No Entra device found matching '{value}'.")
        ids = ", ".join(m.get("displayName", m["id"]) for m in matches)
        raise ValueError(f"'{value}' matches multiple devices: {ids}")

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
