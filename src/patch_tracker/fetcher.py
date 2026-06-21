"""Minimal HTTP JSON fetcher built on the standard library.

Using ``urllib`` keeps the project dependency-free so it runs anywhere with a
Python 3.9+ interpreter. The fetcher is deliberately tiny and injectable: the
source modules accept any ``http_get`` callable, which makes them trivial to
unit-test against local fixtures without network access.
"""

from __future__ import annotations

import gzip
import io
import json
import urllib.error
import urllib.request
from typing import Any

USER_AGENT = "patch-tracker/1.0 (+https://github.com/ajamaya1/patch-tracker)"


class FetchError(RuntimeError):
    """Raised when an HTTP fetch fails for any reason."""


def http_get_json(url: str, timeout: int = 60) -> Any:
    """GET ``url`` and parse the response as JSON.

    Raises :class:`FetchError` with an actionable message on failure. The
    common case in a sandboxed environment is an egress allowlist returning
    HTTP 403 with ``host_not_allowed`` -- we surface that clearly so the user
    knows to add the host to their network settings rather than treating it as
    a code bug.
    """
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.headers.get("Content-Encoding") == "gzip":
                raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:  # pragma: no cover - network path
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")[:200]
        except Exception:
            pass
        hint = ""
        if exc.code == 403 and ("host_not_allowed" in body or "allowlist" in body):
            hint = (
                "\nThis environment's network egress policy is blocking the "
                "host. Add it to your egress allowlist to enable live fetches, "
                "or ingest a saved feed with `--file`."
            )
        raise FetchError(
            f"HTTP {exc.code} fetching {url}: {body}{hint}"
        ) from exc
    except urllib.error.URLError as exc:  # pragma: no cover - network path
        raise FetchError(f"Network error fetching {url}: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise FetchError(f"Invalid JSON from {url}: {exc}") from exc


def load_json_file(path: str) -> Any:
    """Load JSON from a local file (used by `fetch --file`)."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
