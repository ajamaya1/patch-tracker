"""A small Microsoft Graph client over the injectable transport.

Handles the things every Graph caller needs: bearer auth, ``@odata.nextLink``
paging, 429/5xx retry honouring ``Retry-After``, JSON (de)serialisation, and
``$batch`` fan-out. Read-only by default surfaces (``get``/``get_all``) and the
write surfaces (``post``/``patch``) are separate so the assignment engine can
gate writes behind a dry-run flag.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import quote

from .errors import GraphError
from .transport import Response, Transport, make_default_transport

GRAPH_BETA = "https://graph.microsoft.com/beta"
GRAPH_V1 = "https://graph.microsoft.com/v1.0"


class GraphClient:
    def __init__(
        self,
        token_provider: Callable[[], str],
        *,
        base: str = GRAPH_BETA,
        transport: Optional[Transport] = None,
        max_retries: int = 4,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._token = token_provider
        self.base = base.rstrip("/")
        self.transport = transport or make_default_transport()
        self.max_retries = max_retries
        self.sleep = sleep

    # ---- low level ----------------------------------------------------
    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{self.base}/{path.lstrip('/')}"

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[dict] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Response:
        url = self._url(path)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        attempt = 0
        while True:
            headers = {
                "Authorization": f"Bearer {self._token()}",
                "Accept": "application/json",
            }
            if data is not None:
                headers["Content-Type"] = "application/json"
            if extra_headers:
                headers.update(extra_headers)
            resp = self.transport(method, url, headers, data)
            if resp.status in (429, 500, 502, 503, 504) and attempt < self.max_retries:
                delay = _retry_after(resp, attempt)
                self.sleep(delay)
                attempt += 1
                continue
            if resp.status >= 400:
                raise _graph_error(resp, url)
            return resp

    # ---- read ---------------------------------------------------------
    def get(self, path: str, *, extra_headers: Optional[Dict[str, str]] = None) -> Any:
        return self._request("GET", path, extra_headers=extra_headers).json()

    def count(self, path: str) -> int:
        """GET a ``$count`` endpoint (adds the required advanced-query header)."""
        val = self._request(
            "GET", path, extra_headers={"ConsistencyLevel": "eventual"}
        ).json()
        return int(val or 0)

    def get_all(self, path: str, *, page_limit: Optional[int] = None) -> List[dict]:
        """Follow ``@odata.nextLink`` and return all ``value`` entries."""
        items: List[dict] = []
        next_path: Optional[str] = path
        pages = 0
        while next_path:
            data = self._request("GET", next_path).json() or {}
            items.extend(data.get("value", []))
            next_path = data.get("@odata.nextLink")
            pages += 1
            if page_limit and pages >= page_limit:
                break
        return items

    # ---- write --------------------------------------------------------
    def post(self, path: str, body: dict) -> Any:
        resp = self._request("POST", path, body)
        return resp.json() if resp.body else None

    def patch(self, path: str, body: dict) -> Any:
        resp = self._request("PATCH", path, body)
        return resp.json() if resp.body else None

    # ---- batch --------------------------------------------------------
    def batch(self, requests: List[Dict[str, Any]], chunk: int = 20) -> List[Dict[str, Any]]:
        """Execute Graph ``$batch`` requests, chunked to Graph's 20-per limit.

        Each request dict needs ``id``, ``method``, ``url`` (relative to the
        Graph version root, e.g. ``/deviceManagement/...``). Returns the
        flattened ``responses`` list.
        """
        out: List[Dict[str, Any]] = []
        for i in range(0, len(requests), chunk):
            batch_reqs = requests[i : i + chunk]
            resp = self._request("POST", "$batch", {"requests": batch_reqs})
            out.extend((resp.json() or {}).get("responses", []))
        return out


def odata_filter(field: str, value: str) -> str:
    return f"$filter={quote(field)}+eq+'{quote(value)}'"


def _retry_after(resp: Response, attempt: int) -> float:
    ra = resp.header("Retry-After")
    if ra:
        try:
            return float(ra)
        except ValueError:
            pass
    return min(2 ** attempt, 16)


def _graph_error(resp: Response, url: str) -> GraphError:
    code = None
    message = f"HTTP {resp.status}"
    try:
        data = resp.json() or {}
        err = data.get("error", {})
        code = err.get("code")
        message = err.get("message", message)
    except Exception:
        body = resp.body.decode("utf-8", "replace")[:300] if resp.body else ""
        if body:
            message = body
    return GraphError(
        f"Graph {resp.status} on {url}: {message}", status=resp.status, code=code, url=url
    )
