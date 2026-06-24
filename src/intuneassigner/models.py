"""Normalized data model for Intune assignments.

Microsoft Graph represents assignments inconsistently across resource types —
different ``@odata.type`` targets, some with per-assignment ``settings`` or
``intent`` (apps), some without. These dataclasses flatten all of that into a
single shape the CLI, reports and copy/template engine can reason about.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ---- assignment target kinds ------------------------------------------
TARGET_GROUP = "group"
TARGET_EXCLUSION = "exclusion"
TARGET_ALL_USERS = "allUsers"
TARGET_ALL_DEVICES = "allDevices"
TARGET_COLLECTION = "collection"  # ConfigMgr collection
TARGET_UNKNOWN = "unknown"

# Map Graph @odata.type -> (kind, is_exclude)
_TARGET_ODATA = {
    "#microsoft.graph.groupAssignmentTarget": (TARGET_GROUP, False),
    "#microsoft.graph.exclusionGroupAssignmentTarget": (TARGET_EXCLUSION, True),
    "#microsoft.graph.allLicensedUsersAssignmentTarget": (TARGET_ALL_USERS, False),
    "#microsoft.graph.allDevicesAssignmentTarget": (TARGET_ALL_DEVICES, False),
    "#microsoft.graph.configurationManagerCollectionAssignmentTarget": (TARGET_COLLECTION, False),
}

FILTER_TYPE_NONE = "none"


@dataclass
class AssignmentTarget:
    """The 'who' of an assignment: a group, all users/devices, or a collection."""

    kind: str
    group_id: Optional[str] = None
    group_name: Optional[str] = None
    filter_id: Optional[str] = None
    filter_name: Optional[str] = None
    filter_type: str = FILTER_TYPE_NONE  # none | include | exclude
    collection_id: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_exclude(self) -> bool:
        return self.kind == TARGET_EXCLUSION

    @property
    def is_virtual(self) -> bool:
        return self.kind in (TARGET_ALL_USERS, TARGET_ALL_DEVICES)

    def display(self) -> str:
        if self.kind == TARGET_ALL_USERS:
            who = "All Users"
        elif self.kind == TARGET_ALL_DEVICES:
            who = "All Devices"
        elif self.kind == TARGET_COLLECTION:
            who = f"Collection {self.collection_id}"
        else:
            who = self.group_name or self.group_id or "(unknown group)"
        prefix = "EXCLUDE " if self.is_exclude else ""
        if self.filter_id and self.filter_type != FILTER_TYPE_NONE:
            fname = self.filter_name or self.filter_id
            who += f"  [filter {self.filter_type}: {fname}]"
        return prefix + who

    @classmethod
    def from_graph(cls, target: Dict[str, Any]) -> "AssignmentTarget":
        odata = target.get("@odata.type", "")
        kind, _ = _TARGET_ODATA.get(odata, (TARGET_UNKNOWN, False))
        return cls(
            kind=kind,
            group_id=target.get("groupId"),
            collection_id=target.get("collectionId"),
            filter_id=target.get("deviceAndAppManagementAssignmentFilterId"),
            filter_type=(target.get("deviceAndAppManagementAssignmentFilterType") or FILTER_TYPE_NONE),
            raw=dict(target),
        )

    def to_graph(self) -> Dict[str, Any]:
        """Render back to a Graph assignment ``target`` payload."""
        odata = {
            TARGET_GROUP: "#microsoft.graph.groupAssignmentTarget",
            TARGET_EXCLUSION: "#microsoft.graph.exclusionGroupAssignmentTarget",
            TARGET_ALL_USERS: "#microsoft.graph.allLicensedUsersAssignmentTarget",
            TARGET_ALL_DEVICES: "#microsoft.graph.allDevicesAssignmentTarget",
            TARGET_COLLECTION: "#microsoft.graph.configurationManagerCollectionAssignmentTarget",
        }.get(self.kind, "#microsoft.graph.groupAssignmentTarget")
        out: Dict[str, Any] = {"@odata.type": odata}
        if self.kind in (TARGET_GROUP, TARGET_EXCLUSION) and self.group_id:
            out["groupId"] = self.group_id
        if self.kind == TARGET_COLLECTION and self.collection_id:
            out["collectionId"] = self.collection_id
        if self.filter_id and self.filter_type != FILTER_TYPE_NONE:
            out["deviceAndAppManagementAssignmentFilterId"] = self.filter_id
            out["deviceAndAppManagementAssignmentFilterType"] = self.filter_type
        return out

    def match_key(self) -> tuple:
        """Identity used to dedupe targets within one resource's assignment set."""
        return (
            self.kind,
            self.group_id,
            self.collection_id,
            self.filter_id,
            self.filter_type,
        )


@dataclass
class Assignment:
    """One assignment edge: a target plus optional intent/settings (apps)."""

    target: AssignmentTarget
    intent: Optional[str] = None  # apps: required | available | uninstall | ...
    settings: Optional[Dict[str, Any]] = None  # per-assignment settings/notifications
    source: Optional[str] = None  # direct | policySets
    assignment_id: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_graph(cls, item: Dict[str, Any]) -> "Assignment":
        return cls(
            target=AssignmentTarget.from_graph(item.get("target", {}) or {}),
            intent=item.get("intent"),
            settings=item.get("settings"),
            source=item.get("source"),
            assignment_id=item.get("id"),
            raw=dict(item),
        )

    def to_graph(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"target": self.target.to_graph()}
        if self.intent is not None:
            out["intent"] = self.intent
        if self.settings is not None:
            out["settings"] = self.settings
        return out


@dataclass
class ResourceItem:
    """One assignable Intune object plus its resolved assignments."""

    resource_type: str  # registry key, e.g. "configurationPolicies"
    area: str  # human area, e.g. "Configuration"
    id: str
    name: str
    platform: Optional[str] = None
    odata_type: Optional[str] = None
    assignments: List[Assignment] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def includes(self) -> List[Assignment]:
        return [a for a in self.assignments if not a.target.is_exclude]

    @property
    def excludes(self) -> List[Assignment]:
        return [a for a in self.assignments if a.target.is_exclude]

    def targets_group(self, group_id: str) -> List[Assignment]:
        return [a for a in self.assignments if a.target.group_id == group_id]


@dataclass
class GroupRef:
    id: str
    display_name: str
    description: Optional[str] = None
    membership_type: Optional[str] = None  # assigned | dynamic
    security_enabled: Optional[bool] = None

    @classmethod
    def from_graph(cls, item: Dict[str, Any]) -> "GroupRef":
        rule = item.get("membershipRule")
        return cls(
            id=item.get("id", ""),
            display_name=item.get("displayName", ""),
            description=item.get("description"),
            membership_type="dynamic" if rule else "assigned",
            security_enabled=item.get("securityEnabled"),
        )
