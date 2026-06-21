import datetime as dt
import json

from patch_tracker.db import Database
from patch_tracker.models import Cve, Patch
from patch_tracker.site import build_payload, write_site_data


def seed_db():
    db = Database(":memory:")
    apple = Patch(
        source="apple", patch_id="apple:macOS 15.5", title="macOS Sequoia 15.5",
        product="macOS", version="15.5", release_date="2025-05-12T00:00:00Z",
        fetched_at="2025-05-12",
    )
    apple.cves = [
        Cve("CVE-2025-1", apple.patch_id, "apple", exploited=True,
            first_seen="2025-05-12"),
        Cve("CVE-2025-2", apple.patch_id, "apple", first_seen="2020-01-01"),
    ]
    ms = Patch(
        source="microsoft", patch_id="msrc:2025-Jun",
        title="June 2025 Security Updates", product="Microsoft Security Update",
        version="2025-Jun", release_date="2025-06-10T07:00:00Z",
        severity="Critical", fetched_at="2025-06-10",
    )
    ms.cves = [
        Cve("CVE-2025-30000", ms.patch_id, "microsoft", severity="Critical",
            base_score=8.8, exploited=True, first_seen="2025-06-10"),
    ]
    db.upsert_patches([apple, ms])
    return db


def test_build_payload_structure_and_new_flag():
    db = seed_db()
    # Pretend "now" is just after the June release; window 7 days. Use a wide
    # recency window so both seeded patches are present for the structure check.
    now = dt.datetime(2025, 6, 12, tzinfo=dt.timezone.utc)
    payload = build_payload(db, new_days=7, now=now, window_days=3650)

    assert payload["new_window_days"] == 7
    assert payload["stats"]["total_patches"] == 2
    # Only the June CVE (first_seen 2025-06-10) is within the 7-day window.
    assert payload["stats"]["new_cves"] == 1

    by_id = {p["patch_id"]: p for p in payload["patches"]}
    ms = by_id["msrc:2025-Jun"]
    assert ms["patch_tuesday"] == "2025-06-10"
    assert ms["new_count"] == 1
    assert ms["exploited_count"] == 1
    assert ms["cves"][0]["is_new"] is True

    apple = by_id["apple:macOS 15.5"]
    # Apple patch has no Patch Tuesday concept.
    assert apple["patch_tuesday"] is None
    # CVE-2025-2 was first seen in 2020 -> not new.
    flags = {c["cve_id"]: c["is_new"] for c in apple["cves"]}
    assert flags["CVE-2025-2"] is False


def test_microsoft_client_server_breakdown_and_servicing():
    from patch_tracker.sources import microsoft_msrc
    import json, os
    db = Database(":memory:")
    doc = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures",
                                      "msrc_2025_jun_sample.json")))
    summary = {"id": "2025-Jun", "title": "June 2025 Security Updates",
               "release_date": "2025-06-10T07:00:00Z",
               "url": microsoft_msrc.cvrf_url("2025-Jun")}
    db.upsert_patches([microsoft_msrc.parse_cvrf(summary, doc, "2025-06-10")])
    payload = build_payload(db, new_days=7,
                            now=dt.datetime(2025, 6, 12, tzinfo=dt.timezone.utc))
    ms = payload["patches"][0]
    # CVE-2025-30000 affects both client + server; CVE-2025-30001 client only.
    assert ms["affected"]["client"] == 2
    assert ms["affected"]["server"] == 1
    assert ms["servicing"]["channel"] == "B"
    assert ms["servicing"]["hotpatch"]["is_hotpatch_month"] is True
    # Remediation has both client and server sections.
    auds = " ".join(s["audience"] for s in ms["remediation"]["sections"]).lower()
    assert "client" in auds and "server" in auds
    assert payload["stats"]["by_product_kind"].get("server") == 1


def test_window_is_source_aware():
    """Latest MS monthly is always kept; daily sources honour the window."""
    db = Database(":memory:")
    old_apple = Patch(source="apple", patch_id="apple:old", title="old macOS",
                      product="macOS", version="15.1",
                      release_date="2025-01-01T00:00:00Z", fetched_at="x")
    old_apple.cves = [Cve("CVE-A", "apple:old", "apple", first_seen="2025-01-01")]
    new_apple = Patch(source="apple", patch_id="apple:new", title="new macOS",
                      product="macOS", version="15.5",
                      release_date="2025-06-09T00:00:00Z", fetched_at="x")
    new_apple.cves = [Cve("CVE-B", "apple:new", "apple", first_seen="2025-06-09")]
    ms = Patch(source="microsoft", patch_id="msrc:2025-Jun",
               title="June", product="MS", version="2025-Jun",
               release_date="2025-06-10T07:00:00Z", fetched_at="x")
    ms.cves = [Cve("CVE-C", "msrc:2025-Jun", "microsoft", first_seen="2025-06-10")]
    db.upsert_patches([old_apple, new_apple, ms])

    now = dt.datetime(2025, 6, 20, tzinfo=dt.timezone.utc)
    ids = {p["patch_id"] for p in
           build_payload(db, window_days=30, now=now)["patches"]}
    assert ids == {"apple:new", "msrc:2025-Jun"}   # old Apple dropped, MS kept


def test_write_site_data_creates_file(tmp_path):
    db = seed_db()
    out = tmp_path / "nested" / "data.json"
    write_site_data(db, str(out), new_days=7)
    payload = json.loads(out.read_text())
    assert "patches" in payload and "stats" in payload
    assert payload["patches"]  # non-empty
