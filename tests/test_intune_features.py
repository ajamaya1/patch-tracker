"""Tests for compare, what-if (effective assignments), empty groups,
selective copy, new areas, and the HTML report."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from intuneassigner.assignments import AssignmentEngine  # noqa: E402
from intuneassigner.directory import Directory  # noqa: E402
from intuneassigner.graph import GraphClient  # noqa: E402
from intuneassigner import report, resources  # noqa: E402
from intuneassigner.models import Assignment, AssignmentTarget  # noqa: E402
from intune_fake import (  # noqa: E402
    FakeGraph, all_devices_target, all_users_target, grp_target,
)

A = "11111111-1111-1111-1111-111111111111"
B = "22222222-2222-2222-2222-222222222222"
E = "ee000000-0000-0000-0000-0000000000ee"  # empty group
U = "00000000-user-0000-0000-000000000001"
D = "00000000-dev0-0000-0000-000000000001"


@pytest.fixture
def fake():
    fg = FakeGraph()
    fg.add_group(A, "All Workstations", members=5)
    fg.add_group(B, "Pilot Ring", members=2)
    fg.add_group(E, "Stale Group", members=0)
    fg.add_user(U, "jdoe@contoso.com", "Jane Doe", [A])
    fg.add_device(D, "LAPTOP-01", [A])
    fg.add_collection(
        "deviceManagement/configurationPolicies",
        [
            {"id": "cp1", "name": "Win Baseline",
             "assignments": [{"target": grp_target(A)}, {"target": grp_target(B, exclude=True)}]},
            {"id": "cp2", "name": "Only-A Profile",
             "assignments": [{"target": grp_target(A)}]},
            {"id": "cp3", "name": "Stale Profile",
             "assignments": [{"target": grp_target(E)}]},
        ],
    )
    fg.add_collection(
        "deviceAppManagement/mobileApps",
        [{"id": "app1", "displayName": "Edge",
          "assignments": [{"intent": "required", "target": all_devices_target()},
                          {"intent": "available", "target": all_users_target()}]}],
    )
    return fg


def engine(fake):
    client = GraphClient(lambda: "tok", transport=fake)
    return AssignmentEngine(client, Directory(client))


# ---- compare ----------------------------------------------------------
def test_compare_groups(fake):
    eng = engine(fake)
    items = eng.enumerate(keys=["configurationPolicies"])
    cmp = eng.compare_groups(A, B, items)
    only_a = {r["item"].name for r in cmp["only_a"]}
    assert only_a == {"Only-A Profile"}  # cp3 targets E, not A
    both = {r["item"].name for r in cmp["both"]}
    assert both == {"Win Baseline"}  # A include + B exclude
    assert {r["item"].name for r in cmp["conflict"]} == {"Win Baseline"}


# ---- what-if (effective) ---------------------------------------------
def test_effective_for_user(fake):
    eng = engine(fake)
    items = eng.enumerate(only_assigned=True)
    display, gids = eng.dir.subject_groups("user", "jdoe@contoso.com")
    assert display == "Jane Doe"
    assert gids == {A}
    rows = eng.effective_for_subject(gids, items, all_users=True)
    names = {r["item"].name for r in rows if not r["excluded"]}
    # Win Baseline (via A), Only-A Profile (via A), Edge (via All Users). cp3 (E) not a member.
    assert names == {"Win Baseline", "Only-A Profile", "Edge"}


def test_effective_excluded_when_member_of_exclusion(fake):
    eng = engine(fake)
    fake.add_user(U, "boss@contoso.com", "Boss", [A, B])  # also in the excluded group
    items = eng.enumerate(only_assigned=True)
    _, gids = eng.dir.subject_groups("user", "boss@contoso.com")
    rows = eng.effective_for_subject(gids, items, all_users=True)
    win = next(r for r in rows if r["item"].name == "Win Baseline")
    assert win["excluded"] is True  # A includes, B excludes, Boss is in both


def test_effective_for_device_uses_all_devices(fake):
    eng = engine(fake)
    items = eng.enumerate(only_assigned=True)
    display, gids = eng.dir.subject_groups("device", "LAPTOP-01")
    assert display == "LAPTOP-01" and gids == {A}
    rows = eng.effective_for_subject(gids, items, all_devices=True)
    names = {r["item"].name for r in rows}
    assert "Edge" in names  # via All Devices
    assert "Win Baseline" in names  # via group A


# ---- empty groups -----------------------------------------------------
def test_find_empty_targeted_groups(fake):
    eng = engine(fake)
    items = eng.enumerate(only_assigned=True)
    empties = eng.find_empty_targeted_groups(items)
    assert [e["group_name"] for e in empties] == ["Stale Group"]
    assert empties[0]["resources"] == ["Configuration/Stale Profile"]


# ---- selective copy ---------------------------------------------------
def test_selective_copy_only_chosen_ids(fake):
    eng = engine(fake)
    items = eng.enumerate(keys=["configurationPolicies"])
    cands = eng.copy_candidates(A, items)
    assert {c.name for c in cands} == {"Win Baseline", "Only-A Profile"}
    # Mirror only cp2 onto B.
    plans = eng.copy_group(A, B, items, include_ids={"cp2"})
    changed = {p.resource_name for p in plans if p.added}
    assert changed == {"Only-A Profile"}
    assert len([p for p in fake.posts if p["url"].endswith("/assign")]) == 1


# ---- new areas --------------------------------------------------------
def test_new_areas_registered():
    keys = {r.key for r in resources.REGISTRY}
    assert {"cloudPcProvisioningPolicies", "roleScopeTags"} <= keys
    assert "Cloud PC" in resources.AREAS and "Scope tags" in resources.AREAS


def test_copy_preserves_type_specific_assignment_fields():
    # A remediation assignment carries a runSchedule that must survive a copy.
    a = Assignment.from_graph({
        "id": "x", "source": "direct",
        "target": grp_target(A),
        "runRemediationScript": True,
        "runSchedule": {"@odata.type": "#microsoft.graph.deviceHealthScriptDailySchedule",
                        "interval": 1, "time": "01:00"},
    })
    out = a.to_graph()
    assert out["runRemediationScript"] is True
    assert out["runSchedule"]["interval"] == 1
    assert "id" not in out and "source" not in out


def test_cloudpc_target_roundtrips_odata():
    raw = {"@odata.type": "#microsoft.graph.cloudPcManagementGroupAssignmentTarget", "groupId": A}
    t = AssignmentTarget.from_graph(raw)
    assert t.kind == "group" and t.group_id == A
    # Original odata type is preserved on write.
    assert t.to_graph()["@odata.type"] == "#microsoft.graph.cloudPcManagementGroupAssignmentTarget"


# ---- HTML report ------------------------------------------------------
def test_html_report_self_contained(fake):
    eng = engine(fake)
    items = eng.enumerate(only_assigned=True)
    html = report.render_html(items, title="My Tenant")
    assert "<!doctype html>" in html
    assert "My Tenant" in html
    assert "Win Baseline" in html
    assert "DATA =" in html  # data inlined for offline use
