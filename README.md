# patch-tracker

A small, dependency-free CLI for tracking **security patches and your
remediation status** for them, sourced from two authoritative public feeds:

| Source | Vendor | Feed |
| ------ | ------ | ---- |
| **SOFA** | Apple | [`sofa.macadmins.io`](https://sofa.macadmins.io) — macOS/iOS security releases & actively-exploited CVEs |
| **MSRC CVRF v3.0** | Microsoft | [`api.msrc.microsoft.com`](https://github.com/Microsoft/MSRC-Microsoft-Security-Updates-API) — monthly "Patch Tuesday" security updates |

Both feeds are normalized into a common model — a **patch** (a released
update) that fixes one or more **CVEs** — and stored in a local SQLite
database. You can then triage each patch through a tracking workflow
(`new → in_progress → applied / mitigated / wont_fix`), so your remediation
state survives feed refreshes.

> Built with the Python standard library only — no third-party runtime
> dependencies. Runs anywhere with Python 3.9+.

## Install

```bash
pip install -e .
# provides the `patch-tracker` command (and `python -m patch_tracker`)
```

## Quick start

```bash
# Pull the latest data from both vendors (most recent 3 MSRC months + macOS)
patch-tracker fetch

# ...or one vendor, and also include the Apple iOS feed
patch-tracker fetch --source apple --ios
patch-tracker fetch --source microsoft --months 6

# See what's tracked, worst/exploited first
patch-tracker list
patch-tracker list --exploited --severity critical

# Inspect a single patch and every CVE it fixes
patch-tracker show msrc:2025-Jun

# Hunt across all CVEs
patch-tracker cves --exploited
patch-tracker cves --cve CVE-2025-30000

# Triage: record where you are in remediation
patch-tracker status msrc:2025-Jun applied --note "Deployed via WSUS ring 1"
patch-tracker list --status applied

# Dashboard + machine-readable exports
patch-tracker stats
patch-tracker export --format csv --out patches.csv
patch-tracker export --format json
```

Most read commands accept `--json` for scripting.

## Network access

Live `fetch` reaches out to `sofafeed.macadmins.io` and
`api.msrc.microsoft.com`. In a sandboxed environment with an egress
allowlist, add both hosts to your network settings — otherwise `fetch`
fails fast with a clear `host_not_allowed` message.

When you can't (or don't want to) reach the network, ingest a previously
saved feed file:

```bash
patch-tracker fetch --source apple     --file macos_data_feed.json
patch-tracker fetch --source microsoft --file cvrf_2025_Jun.json   # one CVRF doc
```

## Tracking statuses

`new`, `in_progress`, `applied`, `mitigated`, `wont_fix`, `ignored`.
A patch starts as `new` when first ingested; re-fetching never overwrites a
status you've set.

## Data model

```
patches (patch_id PK, source, title, product, version,
         release_date, url, severity, fetched_at)
cves    (cve_id, patch_id, source, severity, impact,
         base_score, exploited, publicly_disclosed, url)   PK (cve_id, patch_id)
tracking(patch_id PK, status, note, updated_at)
```

* **Apple / SOFA** — each OS security release becomes one patch. SOFA flags
  actively-exploited CVEs, which is surfaced as `exploited`.
* **Microsoft / MSRC** — each monthly update becomes one patch; every
  vulnerability becomes a CVE. Severity, impact, CVSS base score and the
  `Exploited` / `Publicly Disclosed` flags are parsed from the CVRF
  `Threats` array.

The database path defaults to `~/.patch-tracker/patches.db` and can be
overridden with `--db <path>` or the `PATCH_TRACKER_DB` environment variable.

## Project layout

```
src/patch_tracker/
  cli.py                 argparse CLI (fetch/list/show/cves/status/stats/export)
  db.py                  SQLite store + queries
  models.py              Patch / Cve dataclasses, severity ranking
  fetcher.py             stdlib HTTP JSON getter (allowlist-aware errors)
  report.py              text-table rendering
  sources/
    apple_sofa.py        SOFA macOS/iOS feed parser
    microsoft_msrc.py    MSRC CVRF v3.0 parser
tests/                   pytest suite + JSON fixtures for both feeds
```

## Development

```bash
pip install -e '.[dev]'
pytest -q
```

The source parsers take an injectable `http_get` callable, so the whole
pipeline is tested offline against fixtures in `tests/fixtures/` that mirror
the real feed schemas.

## License

MIT — see [LICENSE](LICENSE).
