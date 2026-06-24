"""intuneassigner — inspect and manage Microsoft Intune assignments.

A dependency-free toolkit for Intune administrators that answers two
questions the Intune portal makes painfully slow:

* **"What is assigned, and to which groups?"** — across *every* assignable
  area (configuration & settings-catalog profiles, compliance, apps, app
  config/protection, scripts, remediations, Windows Update rings, feature /
  quality / driver update profiles, endpoint-security baselines, enrollment
  configs, …) with group IDs resolved to real display names, include vs.
  exclude intent, assignment filters and per-assignment settings/notifications.

* **"What is *this group* assigned to?"** — the reverse lookup, plus the
  power tools built on top of it: copy every assignment from one group to
  another, bulk-assign a group to many resources, save a set of resources as a
  reusable **template** and stamp new device groups onto it, export to
  CSV/JSON, and generate a tenant-wide **audit report**.

The package is stdlib-only and every network call flows through an injectable
transport, so the whole engine is unit-testable offline against fixtures that
mirror the Microsoft Graph schema — the same philosophy as the sibling
``patch_tracker`` package in this repository.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
