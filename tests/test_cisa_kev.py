import json
import os

from patch_tracker.sources import cisa_kev


def load():
    path = os.path.join(os.path.dirname(__file__), "fixtures",
                        "cisa_kev_sample.json")
    return json.load(open(path))


def test_parse_groups_by_vendor_product_and_excludes_os_vendors():
    patches = cisa_kev.parse_feed(load(), "2025-06-10")
    titles = {p.title for p in patches}
    assert "Google Chromium V8" in titles
    assert "Mozilla Firefox" in titles
    assert "Adobe Acrobat Reader" in titles
    # Microsoft/Apple are covered by dedicated feeds -> excluded by default.
    assert not any("Microsoft" in t for t in titles)


def test_all_kev_cves_marked_exploited():
    patches = cisa_kev.parse_feed(load(), "2025-06-10")
    for p in patches:
        assert p.source == "cisa-kev"
        for c in p.cves:
            assert c.exploited is True
            assert c.first_seen  # dateAdded carried through


def test_ransomware_linked_marked_critical():
    patches = cisa_kev.parse_feed(load(), "2025-06-10")
    adobe = next(p for p in patches if p.title == "Adobe Acrobat Reader")
    assert adobe.cves[0].severity == "Critical"


def test_vendor_filter():
    patches = cisa_kev.parse_feed(load(), "now", vendors={"mozilla"})
    assert len(patches) == 1
    assert patches[0].title == "Mozilla Firefox"


def test_include_os_vendors_opt_in():
    patches = cisa_kev.parse_feed(load(), "now", include_os_vendors=True)
    assert any("Microsoft" in p.title for p in patches)
