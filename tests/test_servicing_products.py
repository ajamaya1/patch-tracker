from patch_tracker.site import windows_servicing, remediation_for
from patch_tracker.sources.microsoft_msrc import classify_product


def test_classify_product():
    assert classify_product("Windows Server 2025 (Server Core installation)") == "server"
    assert classify_product("Windows 11 Version 24H2 for x64-based Systems") == "client"
    assert classify_product("Microsoft Edge (Chromium-based)") == "other"
    assert classify_product("") == "other"


def test_windows_servicing_hotpatch_month():
    # June is a hotpatch month (not a quarterly baseline).
    sv = windows_servicing("2025-Jun")
    assert sv["channel"] == "B"
    assert sv["hotpatch"]["is_hotpatch_month"] is True
    assert sv["hotpatch"]["reboot_required"] is False


def test_windows_servicing_baseline_month():
    # July is a quarterly hotpatch baseline -> cumulative, reboot.
    sv = windows_servicing("2025-Jul")
    assert sv["hotpatch"]["is_hotpatch_month"] is False
    assert sv["hotpatch"]["reboot_required"] is True


def test_remediation_splits_client_and_server():
    rem = remediation_for(
        "microsoft", "Windows", "Microsoft Security Update", "2025-Jun",
        "June 2025 Security Updates", "http://x", exploited_count=1,
        severity="Critical", affected={"client": 5, "server": 3, "other": 0},
    )
    auds = [s["audience"] for s in rem["sections"]]
    assert any("client" in a.lower() for a in auds)
    assert any("server" in a.lower() for a in auds)
    assert rem["urgency"] == "critical"


def test_remediation_third_party_kev():
    rem = remediation_for(
        "cisa-kev", "Google", "Google", None, "Google Chromium V8",
        None, exploited_count=1, severity=None, affected={},
    )
    assert rem["urgency"] == "critical"
    assert any("vendor" in s["steps"][0].lower() for s in rem["sections"])
    assert any("KEV" in l["label"] for l in rem["links"])
