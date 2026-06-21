import datetime as dt

from patch_tracker.site import _priority_score


NOW = dt.datetime(2025, 6, 12, tzinfo=dt.timezone.utc)


def test_exploited_critical_scores_high_band():
    p = _priority_score("Critical", exploited_count=2, new_count=1,
                        max_cvss=9.8, ransomware_count=1,
                        earliest_due=None, now=NOW)
    assert p["band"] == "critical"
    assert "actively exploited" in p["reasons"]
    assert "ransomware-linked" in p["reasons"]


def test_low_severity_unexploited_is_low_band():
    p = _priority_score("Low", exploited_count=0, new_count=0, max_cvss=3.1,
                        ransomware_count=0, earliest_due=None, now=NOW)
    assert p["band"] in ("low", "medium")
    assert p["score"] < 45


def test_overdue_kev_deadline_escalates():
    overdue = _priority_score("High", exploited_count=1, new_count=0,
                              max_cvss=8.0, ransomware_count=0,
                              earliest_due="2025-06-01", now=NOW)
    assert any("overdue" in r for r in overdue["reasons"])
    not_due = _priority_score("High", exploited_count=1, new_count=0,
                              max_cvss=8.0, ransomware_count=0,
                              earliest_due=None, now=NOW)
    assert overdue["score"] > not_due["score"]


def test_score_is_bounded():
    p = _priority_score("Critical", exploited_count=9, new_count=9,
                        max_cvss=10, ransomware_count=9,
                        earliest_due="2000-01-01", now=NOW)
    assert 0 <= p["score"] <= 100
