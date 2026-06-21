import datetime as dt
import json
import os

from patch_tracker.sources import nvd


def load():
    path = os.path.join(os.path.dirname(__file__), "fixtures",
                        "nvd_adobe_sample.json")
    return json.load(open(path))


def test_parse_groups_vendor_and_extracts_scores():
    patches = nvd.parse_feed(load(), "2025-06-11", "Adobe")
    assert len(patches) == 1
    p = patches[0]
    assert p.source == "nvd"
    assert p.patch_id == "nvd:Adobe"
    assert p.product == "Adobe"
    by_id = {c.cve_id: c for c in p.cves}
    # LOW CVE filtered out by default min_severity=HIGH.
    assert "CVE-2025-43502" not in by_id
    assert by_id["CVE-2025-43500"].base_score == 8.8
    assert by_id["CVE-2025-43500"].severity == "High"
    assert by_id["CVE-2025-43501"].severity == "Critical"
    # release_date is the most recent published date.
    assert p.release_date == "2025-06-10"


def test_min_severity_override_includes_low():
    patches = nvd.parse_feed(load(), "now", "Adobe", min_severity="LOW")
    ids = {c.cve_id for c in patches[0].cves}
    assert "CVE-2025-43502" in ids


def test_no_qualifying_cves_returns_empty():
    data = {"vulnerabilities": []}
    assert nvd.parse_feed(data, "now", "Adobe") == []


def test_query_url_has_vendor_and_dates():
    url = nvd.query_url("Adobe", dt.datetime(2025, 5, 1), dt.datetime(2025, 6, 1))
    assert "keywordSearch=Adobe" in url
    assert "pubStartDate=2025-05-01" in url
    assert "pubEndDate=2025-06-01" in url


def test_fetch_uses_injected_http():
    def fake_get(url):
        assert "keywordSearch=Adobe" in url
        return load()
    patches = nvd.fetch(fake_get, "now", vendors=["Adobe"], days=30)
    assert patches and patches[0].title == "Adobe"
