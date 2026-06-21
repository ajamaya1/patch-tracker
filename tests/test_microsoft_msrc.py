from patch_tracker.sources import microsoft_msrc


def test_parse_updates(msrc_updates):
    summaries = microsoft_msrc.parse_updates(msrc_updates)
    ids = {s["id"] for s in summaries}
    assert ids == {"2025-May", "2025-Jun"}
    jun = next(s for s in summaries if s["id"] == "2025-Jun")
    assert jun["title"] == "June 2025 Security Updates"
    assert jun["release_date"] == "2025-06-10T07:00:00Z"


def test_parse_cvrf_extracts_severity_score_and_exploit(msrc_jun):
    summary = {
        "id": "2025-Jun",
        "title": "June 2025 Security Updates",
        "release_date": "2025-06-10T07:00:00Z",
        "url": microsoft_msrc.cvrf_url("2025-Jun"),
    }
    patch = microsoft_msrc.parse_cvrf(summary, msrc_jun, "now")
    assert patch.patch_id == "msrc:2025-Jun"
    assert patch.cve_count == 2
    # Worst severity across the two CVEs is Critical.
    assert patch.severity == "Critical"

    by_id = {c.cve_id: c for c in patch.cves}
    rce = by_id["CVE-2025-30000"]
    assert rce.severity == "Critical"
    assert rce.impact == "Remote Code Execution"
    assert rce.base_score == 8.8
    assert rce.exploited is True
    assert rce.publicly_disclosed is False

    eop = by_id["CVE-2025-30001"]
    assert eop.exploited is False
    assert eop.publicly_disclosed is True
    assert eop.base_score == 7.0


def test_exploit_flag_parser():
    assert microsoft_msrc._exploit_flags(
        [{"Type": 1, "Description": {"Value": "Publicly Disclosed:Yes;Exploited:Yes"}}]
    ) == (True, True)
    assert microsoft_msrc._exploit_flags([]) == (False, False)


def test_fetch_pulls_recent_months(fake_http):
    patches = microsoft_msrc.fetch(fake_http, "now", months=1)
    assert len(patches) == 1
    # months=1 -> most recent only (June)
    assert patches[0].patch_id == "msrc:2025-Jun"
