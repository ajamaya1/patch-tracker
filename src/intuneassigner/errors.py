"""Exception hierarchy for intuneassigner."""

from __future__ import annotations


class IntuneToolError(RuntimeError):
    """Base class for all errors raised by intuneassigner."""


class AuthError(IntuneToolError):
    """Raised when acquiring a Microsoft Graph access token fails."""


class GraphError(IntuneToolError):
    """Raised when a Microsoft Graph API call fails.

    Carries the HTTP ``status`` code and the parsed Graph error ``code`` /
    ``message`` when available so callers can react (e.g. treat 403 on a
    single resource type as "no permission for this area" rather than fatal).
    """

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        code: str | None = None,
        url: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.url = url


class ConfigError(IntuneToolError):
    """Raised when required configuration (tenant, client id, …) is missing."""
