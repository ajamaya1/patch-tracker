from patch_tracker.sources import apple_sofa


def test_parse_feed_maps_releases_to_patches(sofa_macos):
    patches = apple_sofa.parse_feed(sofa_macos, fetched_at="2026-06-21T00:00:00Z")
    assert len(patches) == 2

    latest = next(p for p in patches if p.version == "15.5")
    assert latest.source == "apple"
    assert latest.patch_id == "apple:macOS Sequoia 15.5"
    assert latest.product == "macOS Sequoia"
    assert latest.release_date == "2025-05-12T00:00:00Z"
    assert latest.cve_count == 2
    assert latest.exploited_count == 1


def test_exploited_flag_from_list_and_map(sofa_macos):
    patches = apple_sofa.parse_feed(sofa_macos, "now")
    latest = next(p for p in patches if p.version == "15.5")
    by_id = {c.cve_id: c for c in latest.cves}
    assert by_id["CVE-2025-31200"].exploited is True
    assert by_id["CVE-2025-31201"].exploited is False


def test_fetch_uses_injected_http(fake_http):
    patches = apple_sofa.fetch(fake_http, "now", platforms=("macos",))
    assert any(p.patch_id == "apple:macOS Sequoia 15.5" for p in patches)


def test_empty_feed_is_safe():
    assert apple_sofa.parse_feed({}, "now") == []
    assert apple_sofa.parse_feed({"OSVersions": []}, "now") == []
