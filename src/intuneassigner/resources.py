"""Registry of assignable Intune resource types across every area.

Each :class:`ResourceType` is a declarative description of one assignable
surface in Intune: where to list it on Microsoft Graph, how to read its name
and assignments, and how to write assignments back via the ``/assign`` action.
Adding a new area is a one-entry change — no engine code to touch.

The ``/assign`` action on every Intune resource *replaces the full assignment
set*, so the engine always reads the current assignments, merges, and posts the
complete list back (see :mod:`intuneassigner.assignments`). The per-type
``assign_body_key`` and ``assignment_odata_type`` capture Graph's
frustratingly inconsistent payload shapes.

All paths are relative to the Graph **beta** endpoint, which is where the full
set of Intune assignment surfaces lives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ResourceType:
    key: str
    area: str
    label: str
    list_path: str
    name_field: str = "displayName"
    # GET list with $expand=assignments? If False, fetch /{id}/assignments per item.
    expand_assignments: bool = True
    # Body key for the /assign action payload.
    assign_body_key: str = "assignments"
    # Per-assignment @odata.type required by some assign actions (else omitted).
    assignment_odata_type: Optional[str] = None
    # Some areas are a sub-type of a shared collection (e.g. update rings live
    # inside deviceConfigurations). Filter the list by @odata.type substring.
    odata_type_contains: Optional[str] = None
    # Apps carry an install intent on each assignment.
    has_intent: bool = False
    # $select to keep list payloads small (id + name always added).
    select: tuple = ()
    notes: str = ""

    def assign_path(self, item_id: str) -> str:
        return f"{self.list_path}/{item_id}/assign"

    def assignments_path(self, item_id: str) -> str:
        return f"{self.list_path}/{item_id}/assignments"


# Per-assignment @odata types for the areas that demand them.
_DC_ASSIGN = "#microsoft.graph.deviceConfigurationAssignment"
_APP_ASSIGN = "#microsoft.graph.mobileAppAssignment"

REGISTRY: List[ResourceType] = [
    # ----- Devices > Configuration -----
    ResourceType(
        "configurationPolicies", "Configuration", "Settings catalog profile",
        "deviceManagement/configurationPolicies", name_field="name",
    ),
    ResourceType(
        "deviceConfigurations", "Configuration", "Device configuration profile",
        "deviceManagement/deviceConfigurations",
        assignment_odata_type=_DC_ASSIGN,
    ),
    ResourceType(
        "groupPolicyConfigurations", "Configuration", "Administrative template (ADMX)",
        "deviceManagement/groupPolicyConfigurations",
    ),
    # ----- Devices > Compliance -----
    ResourceType(
        "deviceCompliancePolicies", "Compliance", "Compliance policy",
        "deviceManagement/deviceCompliancePolicies",
    ),
    # ----- Devices > Scripts & remediations -----
    ResourceType(
        "deviceManagementScripts", "Scripts", "Platform / PowerShell script",
        "deviceManagement/deviceManagementScripts", expand_assignments=False,
        assign_body_key="deviceManagementScriptAssignments",
    ),
    ResourceType(
        "deviceShellScripts", "Scripts", "macOS shell script",
        "deviceManagement/deviceShellScripts", expand_assignments=False,
        assign_body_key="deviceManagementScriptAssignments",
    ),
    ResourceType(
        "deviceHealthScripts", "Remediations", "Remediation (health script)",
        "deviceManagement/deviceHealthScripts", expand_assignments=False,
        assign_body_key="deviceHealthScriptAssignments",
    ),
    # ----- Devices > Windows Update -----
    ResourceType(
        "windowsUpdateRings", "Windows Update", "Update ring",
        "deviceManagement/deviceConfigurations",
        assignment_odata_type=_DC_ASSIGN,
        odata_type_contains="windowsUpdateForBusinessConfiguration",
    ),
    ResourceType(
        "windowsFeatureUpdateProfiles", "Windows Update", "Feature update profile",
        "deviceManagement/windowsFeatureUpdateProfiles",
    ),
    ResourceType(
        "windowsQualityUpdateProfiles", "Windows Update", "Quality update profile",
        "deviceManagement/windowsQualityUpdateProfiles",
    ),
    ResourceType(
        "windowsDriverUpdateProfiles", "Windows Update", "Driver update profile",
        "deviceManagement/windowsDriverUpdateProfiles",
    ),
    # ----- Endpoint security -----
    ResourceType(
        "intents", "Endpoint security", "Security baseline / intent",
        "deviceManagement/intents", expand_assignments=False,
    ),
    # ----- Enrollment -----
    ResourceType(
        "deviceEnrollmentConfigurations", "Enrollment", "Enrollment configuration",
        "deviceManagement/deviceEnrollmentConfigurations",
        assign_body_key="enrollmentConfigurationAssignments",
    ),
    # ----- Apps -----
    ResourceType(
        "mobileApps", "Apps", "Application",
        "deviceAppManagement/mobileApps",
        assign_body_key="mobileAppAssignments",
        assignment_odata_type=_APP_ASSIGN,
        has_intent=True,
    ),
    ResourceType(
        "mobileAppConfigurations", "Apps", "App configuration policy",
        "deviceAppManagement/mobileAppConfigurations", expand_assignments=False,
    ),
    ResourceType(
        "targetedManagedAppConfigurations", "Apps", "Managed app config (MAM)",
        "deviceAppManagement/targetedManagedAppConfigurations", expand_assignments=False,
    ),
    ResourceType(
        "iosManagedAppProtections", "App protection", "iOS app protection policy",
        "deviceAppManagement/iosManagedAppProtections", expand_assignments=False,
    ),
    ResourceType(
        "androidManagedAppProtections", "App protection", "Android app protection policy",
        "deviceAppManagement/androidManagedAppProtections", expand_assignments=False,
    ),
    ResourceType(
        "windowsManagedAppProtections", "App protection", "Windows app protection policy",
        "deviceAppManagement/windowsManagedAppProtections", expand_assignments=False,
    ),
]

REGISTRY_BY_KEY: Dict[str, ResourceType] = {r.key: r for r in REGISTRY}
AREAS: List[str] = sorted({r.area for r in REGISTRY})


def resolve_types(
    keys: Optional[List[str]] = None, areas: Optional[List[str]] = None
) -> List[ResourceType]:
    """Select resource types by key and/or area (case-insensitive)."""
    if not keys and not areas:
        return list(REGISTRY)
    out: List[ResourceType] = []
    key_set = {k.lower() for k in (keys or [])}
    area_set = {a.lower() for a in (areas or [])}
    for r in REGISTRY:
        if r.key.lower() in key_set or r.area.lower() in area_set:
            out.append(r)
    return out


def platform_of(item: Dict[str, Any], rt: ResourceType) -> Optional[str]:
    """Best-effort platform label from a Graph object."""
    for field_name in ("platforms", "platform", "platformType"):
        val = item.get(field_name)
        if isinstance(val, str) and val:
            return val
    odata = item.get("@odata.type", "")
    for tag in ("windows", "ios", "macOS", "android"):
        if tag.lower() in odata.lower():
            return tag
    return None
