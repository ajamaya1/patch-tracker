import json
import os

from patch_tracker import cli


def run(args, db_path):
    """Invoke the CLI with an isolated DB; return exit code."""
    return cli.main(["--db", db_path, *args])


def seed(db_path, fixtures_dir):
    macos = os.path.join(fixtures_dir, "sofa_macos_sample.json")
    cvrf = os.path.join(fixtures_dir, "msrc_2025_jun_sample.json")
    assert run(["fetch", "--source", "apple", "--file", macos], db_path) == 0
    assert run(["fetch", "--source", "microsoft", "--file", cvrf], db_path) == 0


def test_fetch_from_file_and_list(tmp_path, capsys):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    db_path = str(tmp_path / "t.db")
    seed(db_path, fixtures)

    capsys.readouterr()
    assert run(["list", "--json"], db_path) == 0
    out = json.loads(capsys.readouterr().out)
    ids = {r["patch_id"] for r in out}
    assert "apple:macOS Sequoia 15.5" in ids
    assert "msrc:2025-Jun" in ids


def test_exploited_filter_cli(tmp_path, capsys):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    db_path = str(tmp_path / "t.db")
    seed(db_path, fixtures)

    capsys.readouterr()
    assert run(["cves", "--exploited", "--json"], db_path) == 0
    out = json.loads(capsys.readouterr().out)
    cve_ids = {r["cve_id"] for r in out}
    assert "CVE-2025-31200" in cve_ids  # Apple exploited
    assert "CVE-2025-30000" in cve_ids  # Microsoft exploited
    assert "CVE-2025-31201" not in cve_ids  # not exploited


def test_status_workflow(tmp_path, capsys):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    db_path = str(tmp_path / "t.db")
    seed(db_path, fixtures)
    capsys.readouterr()

    assert run(["status", "msrc:2025-Jun", "applied", "--note", "patched"],
               db_path) == 0
    capsys.readouterr()
    assert run(["show", "msrc:2025-Jun", "--json"], db_path) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["patch"]["status"] == "applied"
    assert out["patch"]["note"] == "patched"


def test_invalid_status_rejected(tmp_path, capsys):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    db_path = str(tmp_path / "t.db")
    seed(db_path, fixtures)
    assert run(["status", "msrc:2025-Jun", "bogus"], db_path) == 2


def test_stats_and_export_csv(tmp_path, capsys):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    db_path = str(tmp_path / "t.db")
    seed(db_path, fixtures)
    capsys.readouterr()

    assert run(["stats", "--json"], db_path) == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats["total_patches"] == 3  # 2 Apple releases + 1 MSRC month
    assert stats["exploited_cves"] >= 2

    out_csv = str(tmp_path / "out.csv")
    assert run(["export", "--format", "csv", "--out", out_csv], db_path) == 0
    with open(out_csv) as fh:
        content = fh.read()
    assert "CVE-2025-30000" in content
    assert content.startswith("patch_id,source")

    out_html = str(tmp_path / "out.html")
    assert run(["export", "--format", "html", "--out", out_html], db_path) == 0
    with open(out_html) as fh:
        html = fh.read()
    assert "<!DOCTYPE html>" in html
    assert "Patch Tracker report" in html
    assert "CVE-2025-30000" in html


def test_fetch_kev_from_file(tmp_path, capsys):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    db_path = str(tmp_path / "t.db")
    kev = os.path.join(fixtures, "cisa_kev_sample.json")
    assert run(["fetch", "--source", "kev", "--file", kev], db_path) == 0
    capsys.readouterr()
    assert run(["list", "--source", "cisa-kev", "--json"], db_path) == 0
    out = json.loads(capsys.readouterr().out)
    titles = {r["title"] for r in out}
    assert "Google Chromium V8" in titles
    assert "Mozilla Firefox" in titles
