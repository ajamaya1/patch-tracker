"""Unit tests for models, registry, graph paging/retry, report and auth."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from intune_tool import resources  # noqa: E402
from intune_tool.auth import Authenticator  # noqa: E402
from intune_tool.errors import GraphError  # noqa: E402
from intune_tool.graph import GraphClient  # noqa: E402
from intune_tool.models import Assignment, AssignmentTarget, ResourceItem  # noqa: E402
from intune_tool import report  # noqa: E402
from intune_tool.transport import Response  # noqa: E402
from intune_fake import grp_target  # noqa: E402


# ---- models -----------------------------------------------------------
def test_target_roundtrip_group_with_filter():
    t = AssignmentTarget.from_graph(grp_target("g1", filter_id="f1", filter_type="exclude"))
    assert t.kind == "group"
    assert not t.is_exclude
    out = t.to_graph()
    assert out["@odata.type"] == "#microsoft.graph.groupAssignmentTarget"
    assert out["groupId"] == "g1"
    assert out["deviceAndAppManagementAssignmentFilterType"] == "exclude"


def test_exclusion_and_virtual_targets():
    ex = AssignmentTarget.from_graph(grp_target("g1", exclude=True))
    assert ex.is_exclude and ex.kind == "exclusion"
    allu = AssignmentTarget.from_graph({"@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget"})
    assert allu.is_virtual
    assert allu.display() == "All Users"


def test_match_key_dedup():
    a = AssignmentTarget.from_graph(grp_target("g1"))
    b = AssignmentTarget.from_graph(grp_target("g1"))
    assert a.match_key() == b.match_key()


# ---- registry ---------------------------------------------------------
def test_registry_unique_keys_and_resolve():
    keys = [r.key for r in resources.REGISTRY]
    assert len(keys) == len(set(keys))
    apps = resources.resolve_types(areas=["Apps"])
    assert any(r.key == "mobileApps" for r in apps)
    one = resources.resolve_types(keys=["intents"])
    assert len(one) == 1 and one[0].key == "intents"


def test_apps_assign_body_key():
    rt = resources.REGISTRY_BY_KEY["mobileApps"]
    assert rt.assign_body_key == "mobileAppAssignments"
    assert rt.has_intent


# ---- graph client -----------------------------------------------------
def test_paging_follows_nextlink():
    pages = [
        Response(200, {}, json.dumps({"value": [{"id": "1"}], "@odata.nextLink": "https://x/p2"}).encode()),
        Response(200, {}, json.dumps({"value": [{"id": "2"}]}).encode()),
    ]
    calls = []

    def t(method, url, headers, body):
        calls.append(url)
        return pages[len(calls) - 1]

    gc = GraphClient(lambda: "tok", transport=t)
    items = gc.get_all("things")
    assert [i["id"] for i in items] == ["1", "2"]
    assert calls[1] == "https://x/p2"


def test_retry_on_429_then_success():
    seq = [Response(429, {"Retry-After": "0"}, b""), Response(200, {}, b'{"value":[]}')]
    n = {"i": 0}

    def t(method, url, headers, body):
        r = seq[n["i"]]
        n["i"] += 1
        return r

    gc = GraphClient(lambda: "tok", transport=t, sleep=lambda _s: None)
    assert gc.get_all("x") == []
    assert n["i"] == 2


def test_graph_error_surfaces_code():
    def t(method, url, headers, body):
        return Response(403, {}, json.dumps({"error": {"code": "Forbidden", "message": "no"}}).encode())

    gc = GraphClient(lambda: "tok", transport=t)
    with pytest.raises(GraphError) as exc:
        gc.get("x")
    assert exc.value.status == 403
    assert exc.value.code == "Forbidden"


# ---- report -----------------------------------------------------------
def _sample_items():
    t = AssignmentTarget.from_graph(grp_target("g1"))
    t.group_name = "Group One"
    it = ResourceItem(
        resource_type="configurationPolicies", area="Configuration",
        id="cp1", name="Baseline",
        assignments=[Assignment(target=t)],
    )
    empty = ResourceItem("deviceCompliancePolicies", "Compliance", "dc1", "Compliance X")
    return [it, empty]


def test_csv_and_json_export():
    items = _sample_items()
    csv_out = report.to_csv(items)
    assert "Baseline" in csv_out and "Group One" in csv_out
    assert "(unassigned)" in csv_out
    data = json.loads(report.to_json(items))
    assert data[0]["assignments"][0]["group_name"] == "Group One"


def test_audit_counts():
    out = report.render_audit(_sample_items())
    assert "Resources scanned : 2" in out
    assert "unassigned      : 1" in out
    assert "Group One" in out


# ---- auth -------------------------------------------------------------
def test_client_credentials_flow():
    captured = {}

    def t(method, url, headers, body):
        captured["url"] = url
        captured["body"] = body.decode()
        return Response(200, {}, json.dumps({"access_token": "abc", "expires_in": 3600}).encode())

    auth = Authenticator.for_client_credentials("contoso.com", "cid", "secret", transport=t)
    assert auth.token() == "abc"
    assert "grant_type=client_credentials" in captured["body"]
    # cached: second call doesn't re-request.
    assert auth.token() == "abc"


def test_device_code_flow_polls_until_token(tmp_path):
    responses = [
        # devicecode start
        Response(200, {}, json.dumps({
            "device_code": "DEV", "user_code": "ABCD",
            "verification_uri": "https://aka.ms/devicelogin",
            "interval": 0, "expires_in": 900, "message": "go here",
        }).encode()),
        # first poll: pending
        Response(400, {}, json.dumps({"error": "authorization_pending"}).encode()),
        # second poll: success
        Response(200, {}, json.dumps({"access_token": "tok123", "expires_in": 3600}).encode()),
    ]
    n = {"i": 0}

    def t(method, url, headers, body):
        r = responses[n["i"]]
        n["i"] += 1
        return r

    prompts = []
    auth = Authenticator.for_device_code(
        "contoso.com", "cid", transport=t,
        cache_path=tmp_path / "cache.json",
        prompt=lambda uri, code, msg: prompts.append((uri, code)),
        sleep=lambda _s: None,
    )
    assert auth.token() == "tok123"
    assert prompts and prompts[0][1] == "ABCD"
    # token cached to disk
    assert (tmp_path / "cache.json").exists()
