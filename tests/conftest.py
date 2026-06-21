"""Shared test setup: make the src layout importable and load fixtures."""

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name: str):
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def sofa_macos():
    return load_fixture("sofa_macos_sample.json")


@pytest.fixture
def msrc_updates():
    return load_fixture("msrc_updates_sample.json")


@pytest.fixture
def msrc_jun():
    return load_fixture("msrc_2025_jun_sample.json")


@pytest.fixture
def kev_feed():
    return load_fixture("cisa_kev_sample.json")


@pytest.fixture
def fake_http(msrc_updates, msrc_jun, sofa_macos, kev_feed):
    """A stand-in http_get that serves fixtures by URL."""
    from patch_tracker.sources import apple_sofa, cisa_kev, microsoft_msrc

    routes = {
        microsoft_msrc.UPDATES_URL: msrc_updates,
        "https://api.msrc.microsoft.com/cvrf/v3.0/document/2025-Jun": msrc_jun,
        "https://api.msrc.microsoft.com/cvrf/v3.0/document/2025-May": msrc_jun,
        microsoft_msrc.cvrf_url("2025-Jun"): msrc_jun,
        microsoft_msrc.cvrf_url("2025-May"): msrc_jun,
        apple_sofa.MACOS_FEED_URL: sofa_macos,
        apple_sofa.IOS_FEED_URL: sofa_macos,
        cisa_kev.KEV_URL: kev_feed,
    }

    def _get(url: str):
        if url not in routes:
            raise AssertionError(f"unexpected URL requested: {url}")
        return routes[url]

    return _get
