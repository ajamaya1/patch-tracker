"""A fake Microsoft Graph transport for offline intune-tool tests.

Routes GET requests to canned ``value`` payloads (with optional paging),
answers ``/groups/{id}`` and ``$batch`` group lookups from a group table,
resolves ``assignmentFilters``, and records every POST (the ``/assign`` writes)
so tests can assert on the exact bodies the engine sends.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from intune_tool.transport import Response


def grp_target(group_id, exclude=False, filter_id=None, filter_type="include"):
    t = {
        "@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget"
        if exclude
        else "#microsoft.graph.groupAssignmentTarget",
        "groupId": group_id,
    }
    if filter_id:
        t["deviceAndAppManagementAssignmentFilterId"] = filter_id
        t["deviceAndAppManagementAssignmentFilterType"] = filter_type
    return t


def all_devices_target():
    return {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"}


class FakeGraph:
    def __init__(self) -> None:
        # path-fragment -> list of objects (each may carry "assignments")
        self.collections: Dict[str, List[dict]] = {}
        # exact-ish fragment -> list (for /{id}/assignments)
        self.assignment_routes: Dict[str, List[dict]] = {}
        self.groups: Dict[str, dict] = {}
        self.filters: List[dict] = []
        self.posts: List[Dict[str, Any]] = []

    # ---- setup helpers ------------------------------------------------
    def add_collection(self, path_fragment: str, items: List[dict]) -> None:
        self.collections[path_fragment] = items

    def add_group(self, gid: str, name: str, **extra) -> None:
        self.groups[gid] = {"id": gid, "displayName": name, **extra}

    def add_filter(self, fid: str, name: str) -> None:
        self.filters.append({"id": fid, "displayName": name})

    # ---- transport ----------------------------------------------------
    def __call__(self, method, url, headers, body) -> Response:
        if method == "GET":
            return self._get(url)
        if method == "POST":
            return self._post(url, body)
        return Response(405, {}, b"")

    def _json(self, obj) -> Response:
        return Response(200, {"Content-Type": "application/json"}, json.dumps(obj).encode())

    def _get(self, url: str) -> Response:
        # assignment filters
        if "assignmentFilters" in url:
            return self._json({"value": self.filters})
        # single group read
        if "/groups/" in url and "$filter" not in url:
            gid = url.split("/groups/")[1].split("?")[0]
            grp = self.groups.get(gid)
            if grp:
                return self._json(grp)
            return Response(404, {}, b'{"error":{"code":"NotFound"}}')
        # group by displayName filter
        if url.rstrip("/").endswith("groups") is False and "groups?$filter=displayName" in url:
            name = url.split("displayName eq '")[1].split("'")[0]
            matches = [g for g in self.groups.values() if g["displayName"].lower() == name.lower()]
            return self._json({"value": matches})
        # per-item assignments routes
        for frag, items in self.assignment_routes.items():
            if frag in url:
                return self._json({"value": items})
        # collections (match the longest fragment that appears in the URL)
        best = None
        for frag in self.collections:
            if frag in url and (best is None or len(frag) > len(best)):
                best = frag
        if best is not None:
            return self._json({"value": self.collections[best]})
        # unknown -> empty collection (lets unrelated areas no-op)
        return self._json({"value": []})

    def _post(self, url: str, body) -> Response:
        payload = json.loads(body.decode()) if body else {}
        if url.endswith("$batch"):
            return self._batch(payload)
        self.posts.append({"url": url, "body": payload})
        return Response(200, {}, b"")

    def _batch(self, payload) -> Response:
        responses = []
        for req in payload.get("requests", []):
            rid = req["id"]
            u = req["url"]
            gid = u.split("/groups/")[1].split("?")[0]
            grp = self.groups.get(gid)
            if grp:
                responses.append({"id": rid, "status": 200, "body": grp})
            else:
                responses.append({"id": rid, "status": 404, "body": {}})
        return self._json({"responses": responses})
