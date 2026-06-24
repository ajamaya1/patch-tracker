"""End-to-end engine tests against an offline fake Graph."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from intuneassigner.assignments import AssignmentEngine  # noqa: E402
from intuneassigner.directory import Directory  # noqa: E402
from intuneassigner.graph import GraphClient  # noqa: E402
from intune_fake import FakeGraph, all_devices_target, grp_target  # noqa: E402

A = "11111111-1111-1111-1111-111111111111"
B = "22222222-2222-2222-2222-222222222222"
C = "33333333-3333-3333-3333-333333333333"
F1 = "ffffffff-0000-0000-0000-000000000001"


@pytest.fixture
def fake():
    fg = FakeGraph()
    fg.add_group(A, "All Workstations")
    fg.add_group(B, "Pilot Ring")
    fg.add_group(C, "New Devices")
    fg.add_filter(F1, "Corp Windows")
    # Settings-catalog (expand=assignments, name field is "name")
    fg.add_collection(
        "deviceManagement/configurationPolicies",
        [
            {
                "id": "cp1",
                "name": "Win Baseline",
                "assignments": [
                    {"target": grp_target(A, filter_id=F1)},
                    {"target": grp_target(B, exclude=True)},
                ],
            },
            {"id": "cp2", "name": "Mac Baseline", "assignments": []},
        ],
    )
    # Apps (expand, with intent + settings)
    fg.add_collection(
        "deviceAppManagement/mobileApps",
        [
            {
                "id": "app1",
                "displayName": "Company Portal",
                "assignments": [
                    {
                        "intent": "required",
                        "target": grp_target(A),
                        "settings": {"@odata.type": "#microsoft.graph.win32LobAppAssignmentSettings",
                                     "notifications": "showReboot"},
                    },
                    {"intent": "available", "target": all_devices_target()},
                ],
            }
        ],
    )
    # Scripts (no expand -> per-item assignments fetch)
    fg.add_collection(
        "deviceManagement/deviceManagementScripts",
        [{"id": "scr1", "displayName": "Set Wallpaper"}],
    )
    fg.assignment_routes["deviceManagementScripts/scr1/assignments"] = [
        {"target": grp_target(A)}
    ]
    return fg


def make_engine(fake):
    client = GraphClient(lambda: "tok", transport=fake)
    return AssignmentEngine(client, Directory(client))


def test_enumerate_resolves_groups_filters_and_intent(fake):
    eng = make_engine(fake)
    items = eng.enumerate(only_assigned=True)
    by_name = {it.name: it for it in items}
    assert set(by_name) == {"Win Baseline", "Company Portal", "Set Wallpaper"}

    cp = by_name["Win Baseline"]
    inc = cp.includes[0].target
    assert inc.group_name == "All Workstations"
    assert inc.filter_name == "Corp Windows"
    assert inc.filter_type == "include"
    assert cp.excludes[0].target.group_name == "Pilot Ring"

    app = by_name["Company Portal"]
    intents = {a.intent for a in app.assignments}
    assert intents == {"required", "available"}
    assert any(a.target.kind == "allDevices" for a in app.assignments)

    # Per-item (non-expanded) assignment fetch worked.
    assert by_name["Set Wallpaper"].assignments[0].target.group_name == "All Workstations"


def test_by_group_reverse_lookup(fake):
    eng = make_engine(fake)
    items = eng.enumerate(only_assigned=True)
    hits = eng.by_group(A, items)
    names = sorted(it.name for it, _ in hits)
    assert names == ["Company Portal", "Set Wallpaper", "Win Baseline"]
    # Pilot Ring (exclusion only) is found too.
    assert [it.name for it, _ in eng.by_group(B, items)] == ["Win Baseline"]


def test_copy_group_appends_and_writes(fake):
    eng = make_engine(fake)
    items = eng.enumerate(only_assigned=True)
    plans = eng.copy_group(A, C, items)
    changed = {p.resource_name for p in plans if p.added}
    assert changed == {"Win Baseline", "Company Portal", "Set Wallpaper"}

    # Three /assign POSTs, each preserving originals plus the new C target.
    assigns = [p for p in fake.posts if p["url"].endswith("/assign")]
    assert len(assigns) == 3

    cp_post = next(p for p in fake.posts if "configurationPolicies/cp1/assign" in p["url"])
    gids = [
        a["target"].get("groupId")
        for a in cp_post["body"]["assignments"]
    ]
    assert A in gids and B in gids and C in gids  # original A+B kept, C added
    # Copied edge preserved the include filter.
    c_assign = next(a for a in cp_post["body"]["assignments"] if a["target"].get("groupId") == C)
    assert c_assign["target"]["deviceAndAppManagementAssignmentFilterId"] == F1

    # App copy preserves intent + settings and uses the apps body key.
    app_post = next(p for p in fake.posts if "mobileApps/app1/assign" in p["url"])
    new_app = next(
        a for a in app_post["body"]["mobileAppAssignments"] if a["target"].get("groupId") == C
    )
    assert new_app["intent"] == "required"
    assert new_app["settings"]["notifications"] == "showReboot"


def test_copy_dry_run_writes_nothing(fake):
    eng = make_engine(fake)
    items = eng.enumerate(only_assigned=True)
    plans = eng.copy_group(A, C, items, dry_run=True)
    assert any(p.added for p in plans)
    assert fake.posts == []  # nothing written
    assert all(not p.applied for p in plans)


def test_bulk_assign_skips_existing(fake):
    eng = make_engine(fake)
    items = eng.enumerate(keys=["configurationPolicies"])
    plans = eng.bulk_assign(C, items)
    assert {p.resource_name for p in plans if p.added} == {"Win Baseline", "Mac Baseline"}
    # cp already targeting C? No — both get C. Two writes.
    assert len([p for p in fake.posts if p["url"].endswith("/assign")]) == 2

    # Idempotency: re-adding an identical target is skipped. scr1 already
    # targets A with no filter, so a plain A target is a no-op.
    scripts = eng.enumerate(keys=["deviceManagementScripts"])
    plans_a = eng.bulk_assign(A, scripts)
    assert all(p.skipped_reason == "already assigned" for p in plans_a)


def test_template_roundtrip_and_apply(fake):
    eng = make_engine(fake)
    items = eng.enumerate(only_assigned=True)
    tmpl = eng.template_from_group(A, items, name="Baseline")
    types = {r.resource_type for r in tmpl.resources}
    assert types == {"configurationPolicies", "mobileApps", "deviceManagementScripts"}

    # Apply to a fresh group.
    plans = eng.apply_template(tmpl, C, items, dry_run=True)
    assert {p.resource_name for p in plans if p.added} == {
        "Win Baseline", "Company Portal", "Set Wallpaper"
    }
