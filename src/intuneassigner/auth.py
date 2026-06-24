"""Microsoft Entra ID (Azure AD) authentication for Microsoft Graph.

Two flows, both implemented with the standard library on top of the injectable
:mod:`transport` (no MSAL dependency):

* **Device code** (delegated) — interactive sign-in as yourself. The tool prints
  a URL and a code; you approve in a browser; the tool then has *your* Intune
  permissions and respects your RBAC. Best for hands-on admin work.

* **Client credentials** (app-only) — unattended sign-in with an app
  registration's client id + secret. Best for scheduled audit/reporting.

Delegated tokens are cached (with their refresh token) under
``~/.intuneassigner/token-cache.json`` so you sign in once per session window.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .errors import AuthError, ConfigError
from .transport import Transport, make_default_transport

AUTHORITY = "https://login.microsoftonline.com"
GRAPH_DEFAULT_SCOPE = "https://graph.microsoft.com/.default"
# Delegated scopes covering every Intune assignment area this tool touches.
DELEGATED_SCOPES = (
    "https://graph.microsoft.com/DeviceManagementConfiguration.ReadWrite.All "
    "https://graph.microsoft.com/DeviceManagementApps.ReadWrite.All "
    "https://graph.microsoft.com/DeviceManagementServiceConfig.ReadWrite.All "
    "https://graph.microsoft.com/DeviceManagementManagedDevices.Read.All "
    "https://graph.microsoft.com/Group.Read.All "
    "https://graph.microsoft.com/Directory.Read.All "
    "offline_access"
)
# Public client id for "Microsoft Graph Command Line Tools" — usable for
# device-code sign-in without registering your own app. Override with
# INTUNEASSIGNER_CLIENT_ID to use your own public client.
DEFAULT_PUBLIC_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

DEFAULT_CACHE_PATH = Path.home() / ".intuneassigner" / "token-cache.json"


@dataclass
class Token:
    access_token: str
    expires_at: float  # epoch seconds
    refresh_token: Optional[str] = None

    @property
    def expired(self) -> bool:
        # 60s safety margin.
        return time.time() >= (self.expires_at - 60)


def _form(transport: Transport, url: str, fields: dict) -> dict:
    body = urllib.parse.urlencode(fields).encode("utf-8")
    resp = transport(
        "POST",
        url,
        {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        body,
    )
    try:
        data = resp.json() or {}
    except Exception:
        data = {}
    return {"_status": resp.status, **data}


class Authenticator:
    """Acquires and refreshes Graph access tokens.

    Pick a flow with :meth:`for_device_code` or :meth:`for_client_credentials`.
    Call :meth:`token` to get a valid bearer string (refreshing/caching as
    needed).
    """

    def __init__(
        self,
        tenant: str,
        client_id: str,
        *,
        client_secret: Optional[str] = None,
        flow: str = "device_code",
        transport: Optional[Transport] = None,
        cache_path: Optional[Path] = None,
        prompt: Optional[Callable[[str, str, str], None]] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not tenant:
            raise ConfigError("A tenant id or domain is required (set INTUNE_TENANT).")
        if not client_id:
            raise ConfigError("A client id is required (set INTUNEASSIGNER_CLIENT_ID).")
        self.tenant = tenant
        self.client_id = client_id
        self.client_secret = client_secret
        self.flow = flow
        self.transport = transport or make_default_transport()
        self.cache_path = cache_path or DEFAULT_CACHE_PATH
        self.prompt = prompt or _default_prompt
        self.sleep = sleep
        self._token: Optional[Token] = None

    # ---- constructors -------------------------------------------------
    @classmethod
    def for_device_code(cls, tenant: str, client_id: str, **kw) -> "Authenticator":
        return cls(tenant, client_id, flow="device_code", **kw)

    @classmethod
    def for_client_credentials(
        cls, tenant: str, client_id: str, client_secret: str, **kw
    ) -> "Authenticator":
        if not client_secret:
            raise ConfigError("Client-credentials flow requires a client secret.")
        return cls(
            tenant, client_id, client_secret=client_secret, flow="client_credentials", **kw
        )

    @classmethod
    def from_env(cls, **kw) -> "Authenticator":
        """Build from environment variables.

        ``INTUNE_TENANT``, ``INTUNEASSIGNER_CLIENT_ID`` (defaults to the public
        Graph CLI client), ``INTUNE_CLIENT_SECRET`` (presence selects app-only),
        ``INTUNE_AUTH_FLOW`` (``device_code``/``client_credentials``).
        """
        tenant = os.environ.get("INTUNE_TENANT", "")
        client_id = os.environ.get("INTUNEASSIGNER_CLIENT_ID", DEFAULT_PUBLIC_CLIENT_ID)
        secret = os.environ.get("INTUNE_CLIENT_SECRET")
        flow = os.environ.get("INTUNE_AUTH_FLOW") or (
            "client_credentials" if secret else "device_code"
        )
        return cls(
            tenant, client_id, client_secret=secret, flow=flow, **kw
        )

    # ---- public -------------------------------------------------------
    def token(self) -> str:
        """Return a valid access token, refreshing or signing in as needed."""
        if self._token and not self._token.expired:
            return self._token.access_token
        if self.flow == "client_credentials":
            self._token = self._client_credentials()
            return self._token.access_token
        # delegated: try cache, then refresh, then device-code sign-in.
        cached = self._load_cache()
        if cached and not cached.expired:
            self._token = cached
            return cached.access_token
        if cached and cached.refresh_token:
            refreshed = self._refresh(cached.refresh_token)
            if refreshed:
                self._token = refreshed
                self._save_cache(refreshed)
                return refreshed.access_token
        tok = self._device_code()
        self._token = tok
        self._save_cache(tok)
        return tok.access_token

    # ---- flows --------------------------------------------------------
    def _token_url(self) -> str:
        return f"{AUTHORITY}/{self.tenant}/oauth2/v2.0/token"

    def _client_credentials(self) -> Token:
        data = _form(
            self.transport,
            self._token_url(),
            {
                "client_id": self.client_id,
                "client_secret": self.client_secret or "",
                "scope": GRAPH_DEFAULT_SCOPE,
                "grant_type": "client_credentials",
            },
        )
        return _token_from_response(data)

    def _refresh(self, refresh_token: str) -> Optional[Token]:
        data = _form(
            self.transport,
            self._token_url(),
            {
                "client_id": self.client_id,
                "scope": DELEGATED_SCOPES,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
        )
        if data.get("_status") != 200 or "access_token" not in data:
            return None
        return _token_from_response(data)

    def _device_code(self) -> Token:
        dc_url = f"{AUTHORITY}/{self.tenant}/oauth2/v2.0/devicecode"
        start = _form(
            self.transport,
            dc_url,
            {"client_id": self.client_id, "scope": DELEGATED_SCOPES},
        )
        if "device_code" not in start:
            raise AuthError(
                f"Could not start device-code sign-in: {start.get('error_description', start)}"
            )
        self.prompt(
            start.get("verification_uri", "https://microsoft.com/devicelogin"),
            start.get("user_code", "?"),
            start.get("message", ""),
        )
        interval = int(start.get("interval", 5))
        expires_in = int(start.get("expires_in", 900))
        device_code = start["device_code"]
        deadline = time.time() + expires_in
        while time.time() < deadline:
            self.sleep(interval)
            data = _form(
                self.transport,
                self._token_url(),
                {
                    "client_id": self.client_id,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                },
            )
            if "access_token" in data:
                return _token_from_response(data)
            err = data.get("error")
            if err == "authorization_pending":
                continue
            if err == "slow_down":
                interval += 5
                continue
            raise AuthError(
                f"Device-code sign-in failed: {data.get('error_description', err)}"
            )
        raise AuthError("Device-code sign-in timed out before approval.")

    # ---- token cache --------------------------------------------------
    def _load_cache(self) -> Optional[Token]:
        try:
            raw = json.loads(self.cache_path.read_text("utf-8"))
        except (OSError, ValueError):
            return None
        entry = raw.get(self._cache_key())
        if not entry:
            return None
        return Token(
            access_token=entry.get("access_token", ""),
            expires_at=entry.get("expires_at", 0),
            refresh_token=entry.get("refresh_token"),
        )

    def _save_cache(self, tok: Token) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                raw = json.loads(self.cache_path.read_text("utf-8"))
            except (OSError, ValueError):
                raw = {}
            raw[self._cache_key()] = {
                "access_token": tok.access_token,
                "expires_at": tok.expires_at,
                "refresh_token": tok.refresh_token,
            }
            self.cache_path.write_text(json.dumps(raw), "utf-8")
            try:
                os.chmod(self.cache_path, 0o600)
            except OSError:
                pass
        except OSError:
            # Caching is best-effort; never fail auth because of disk issues.
            pass

    def _cache_key(self) -> str:
        return f"{self.tenant}:{self.client_id}"


def _token_from_response(data: dict) -> Token:
    if "access_token" not in data:
        raise AuthError(
            f"Token endpoint returned no access_token: "
            f"{data.get('error_description', data.get('error', data))}"
        )
    expires_in = int(data.get("expires_in", 3600))
    return Token(
        access_token=data["access_token"],
        expires_at=time.time() + expires_in,
        refresh_token=data.get("refresh_token"),
    )


def _default_prompt(verification_uri: str, user_code: str, message: str) -> None:  # pragma: no cover
    if message:
        print(message)
    else:
        print(f"To sign in, open {verification_uri} and enter code: {user_code}")
