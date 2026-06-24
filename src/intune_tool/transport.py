"""HTTP transport for Microsoft Graph, built on the standard library.

Every network call in intune-tool flows through a ``Transport`` callable with
the signature::

    transport(method, url, headers, body) -> Response

This single seam keeps the package dependency-free (``urllib`` under the hood)
*and* trivially testable: unit tests inject a fake transport backed by JSON
fixtures, so the entire Graph engine runs offline.
"""

from __future__ import annotations

import gzip
import io
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Mapping, Optional

from .errors import GraphError

USER_AGENT = "intune-tool/0.1 (+https://github.com/ajamaya1/patch-tracker)"


@dataclass
class Response:
    """A minimal HTTP response."""

    status: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""

    def json(self):
        if not self.body:
            return None
        return json.loads(self.body.decode("utf-8"))

    def header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        # Case-insensitive header lookup.
        lname = name.lower()
        for k, v in self.headers.items():
            if k.lower() == lname:
                return v
        return default


# A Transport sends one request and returns a Response. It must NOT raise on
# non-2xx HTTP statuses — it returns the Response and lets the Graph client
# decide (so 429/5xx can be retried and 403/404 handled per-resource).
Transport = Callable[[str, str, Mapping[str, str], Optional[bytes]], Response]


def urllib_transport(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: Optional[bytes],
    *,
    timeout: int = 60,
) -> Response:
    """Default transport using :mod:`urllib`.

    Surfaces sandbox egress-allowlist denials with an actionable hint, mirroring
    the sibling ``patch_tracker.fetcher`` behaviour.
    """
    req = urllib.request.Request(url, data=body, method=method.upper())
    for k, v in headers.items():
        req.add_header(k, v)
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept-Encoding", "gzip")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.headers.get("Content-Encoding") == "gzip":
                raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
            return Response(resp.status, dict(resp.headers), raw)
    except urllib.error.HTTPError as exc:  # pragma: no cover - network path
        raw = b""
        try:
            raw = exc.read()
            if exc.headers.get("Content-Encoding") == "gzip":
                raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
        except Exception:
            pass
        body_txt = raw.decode("utf-8", "replace")
        if exc.code == 403 and ("host_not_allowed" in body_txt or "allowlist" in body_txt):
            raise GraphError(
                "Network egress policy blocked the request to "
                f"{url}. Add login.microsoftonline.com and graph.microsoft.com "
                "to your environment's egress allowlist.",
                status=403,
                url=url,
            ) from exc
        return Response(exc.code, dict(exc.headers or {}), raw)
    except urllib.error.URLError as exc:  # pragma: no cover - network path
        raise GraphError(f"Network error contacting {url}: {exc.reason}", url=url) from exc


def make_default_transport(timeout: int = 60) -> Transport:
    """Build a urllib transport bound to a timeout."""

    def _t(method, url, headers, body):
        return urllib_transport(method, url, headers, body, timeout=timeout)

    return _t
