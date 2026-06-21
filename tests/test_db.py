from patch_tracker.db import Database
from patch_tracker.models import Cve, Patch


def make_patch(patch_id="apple:test", exploited=False):
    p = Patch(
        source="apple", patch_id=patch_id, title="Test Patch",
        product="macOS", version="15.5", release_date="2025-05-12T00:00:00Z",
        severity="Critical", fetched_at="now",
    )
    p.cves = [
        Cve(cve_id="CVE-2025-1", patch_id=patch_id, source="apple",
            severity="Critical", exploited=exploited),
        Cve(cve_id="CVE-2025-2", patch_id=patch_id, source="apple"),
    ]
    return p


def test_upsert_and_list():
    db = Database(":memory:")
    assert db.upsert_patches([make_patch()]) == 1
    rows = db.list_patches()
    assert len(rows) == 1
    assert rows[0]["cve_count"] == 2
    assert rows[0]["status"] == "new"


def test_reingest_preserves_status():
    db = Database(":memory:")
    db.upsert_patches([make_patch()])
    assert db.set_status("apple:test", "applied", "done", "now") is True
    # Re-ingest the same patch; tracking status must survive.
    db.upsert_patches([make_patch()])
    patch = db.get_patch("apple:test")
    assert patch["status"] == "applied"
    assert patch["note"] == "done"


def test_set_status_unknown_patch():
    db = Database(":memory:")
    assert db.set_status("nope", "applied", None, "now") is False


def test_exploited_filter():
    db = Database(":memory:")
    db.upsert_patches([
        make_patch("apple:a", exploited=True),
        make_patch("apple:b", exploited=False),
    ])
    rows = db.list_patches(exploited_only=True)
    assert [r["patch_id"] for r in rows] == ["apple:a"]


def test_list_cves_and_stats():
    db = Database(":memory:")
    db.upsert_patches([make_patch("apple:a", exploited=True)])
    exploited = db.list_cves(exploited_only=True)
    assert len(exploited) == 1
    assert exploited[0]["cve_id"] == "CVE-2025-1"

    s = db.stats()
    assert s["total_patches"] == 1
    assert s["total_cves"] == 2
    assert s["exploited_cves"] == 1
    assert s["by_source"] == {"apple": 1}


def test_first_seen_is_preserved_across_reingest():
    db = Database(":memory:")
    p = make_patch()
    p.cves[0].first_seen = "2020-01-01"  # pretend it was first seen long ago
    p.cves[1].first_seen = "2020-02-02"
    db.upsert_patches([p])
    # Re-ingest the same patch with no first_seen set (as parsers produce).
    db.upsert_patches([make_patch()])
    rows = {r["cve_id"]: r for r in db.get_cves_for_patch("apple:test")}
    assert rows["CVE-2025-1"]["first_seen"] == "2020-01-01"
    # Older CVE is not counted as new in a recent window.
    assert db.count_new_cves("2025-01-01") == 0


def test_upsert_removes_stale_cves():
    db = Database(":memory:")
    db.upsert_patches([make_patch()])
    # Re-ingest with a single CVE; the old second CVE should be gone.
    p = make_patch()
    p.cves = p.cves[:1]
    db.upsert_patches([p])
    assert len(db.get_cves_for_patch("apple:test")) == 1
