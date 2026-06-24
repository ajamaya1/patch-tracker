"""A fake Microsoft Graph transport for offline intuneassigner tests.

Routes GET requests to canned ``value`` payloads (with optional paging),
answers ``/groups/{id}`` and ``$batch`` group lookups from a group table,
resolves ``assignmentFilters``, serves user/device ``transitiveMemberOf`` and
group ``members/$count``, and records every POST (the ``/assign`` writes) so
tests can assert on the exact bodies the engine sends.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

from intuneassigner.transport import Response


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


def all_users_target():
    return {"@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget"}


class FakeGraph:
    def __init__(self) -> None:
        self.collections: Dict[str, List[dict]] = {}
        self.assignment_routes: Dict[str, List[dict]] = {}
        self.groups: Dict[str, dict] = {}
        self.filters: List[dict] = []
        self.posts: List[Dict[str, Any]] = []
        self.users: Dict[str, dict] = {}
        self.devices: Dict[str, dict] = {}
        self.memberships: Dict[str, List[str]] = {}  # subject id/upn -> [group id]
        self.counts: Dict[str, int] = {}  # group id -> member count

    # ---- setup helpers ------------------------------------------------
    def add_collection(self, path_fragment: str, items: List[dict]) -> None:
        self.collections[path_fragment] = items

    def add_group(self, gid: str, name: str, *, members: int = 1, **extra) -> None:
        self.groups[gid] = {"id": gid, "displayName": name, **extra}
        self.counts[gid] = members

    def add_filter(self, fid: str, name: str) -> None:
        self.filters.append({"id": fid, "displayName": name})

    def add_user(self, uid: str, upn: str, display: str, group_ids: List[str]) -> None:
        self.users[uid] = {"id": uid, "displayName": display, "userPrincipalName": upn}
        self.users[upn] = self.users[uid]
        self.memberships[uid] = list(group_ids)
        self.memberships[upn] = list(group_ids)

    def add_device(self, did: str, name: str, group_ids: List[str]) -> None:
        self.devices[did] = {"id": did, "displayName": name, "deviceId": did}
        self.memberships[did] = list(group_ids)

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
        # ---- membership / count (check before the generic /groups/ block) ----
        if "/members/$count" in url:
            gid = url.split("/groups/")[1].split("/members")[0]
            return Response(200, {}, str(self.counts.get(gid, 0)).encode())
        if "transitiveMemberOf" in url:
            subj = url.split("/")[-2] if url.split("/")[-1].startswith("microsoft.graph") \
                else url.split("transitiveMemberOf")[0].rstrip("/").split("/")[-1]
            # subject id is the path segment before /transitiveMemberOf
            subj = url.split("transitiveMemberOf")[0].rstrip("/").split("/")[-1]
            gids = self.memberships.get(subj, [])
            return self._json({"value": [self.groups[g] for g in gids if g in self.groups]})
        if "/users/" in url:
            uid = unquote(url.split("/users/")[1].split("?")[0])
            u = self.users.get(uid)
            return self._json(u) if u else Response(404, {}, b'{"error":{"code":"NotFound"}}')
        if "/devices" in url and "$filter=displayName" in url:
            name = url.split("displayName eq '")[1].split("'")[0]
            matches = [d for d in self.devices.values() if d["displayName"] == name]
            return self._json({"value": matches})
        if "/devices/" in url:
            did = url.split("/devices/")[1].split("?")[0]
            d = self.devices.get(did)
            return self._json(d) if d else Response(404, {}, b'{"error":{"code":"NotFound"}}')
        # ---- assignment filters ----
        if "assignmentFilters" in url:
            return self._json({"value": self.filters})
        # ---- single group read ----
        if "/groups/" in url and "$filter" not in url:
            gid = url.split("/groups/")[1].split("?")[0]
            grp = self.groups.get(gid)
            return self._json(grp) if grp else Response(404, {}, b'{"error":{"code":"NotFound"}}')
        # ---- group by displayName ----
        if "groups?$filter=displayName" in url:
            name = url.split("displayName eq '")[1].split("'")[0]
            matches = [g for g in self.groups.values() if g["displayName"].lower() == name.lower()]
            return self._json({"value": matches})
        # ---- per-item assignments routes ----
        for frag, items in self.assignment_routes.items():
            if frag in url:
                return self._json({"value": items})
        # ---- collections (longest matching fragment) ----
        best = None
        for frag in self.collections:
            if frag in url and (best is None or len(frag) > len(best)):
                best = frag
        if best is not None:
            return self._json({"value": self.collections[best]})
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
            gid = req["url"].split("/groups/")[1].split("?")[0]
            grp = self.groups.get(gid)
            responses.append(
                {"id": req["id"], "status": 200 if grp else 404, "body": grp or {}}
            )
        return self._json({"responses": responses})
