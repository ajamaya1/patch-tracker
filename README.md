# patch-tracker

An auto-updating **security patch dashboard** plus a dependency-free CLI,
tracking patches and remediation status sourced from two authoritative public
feeds. A GitHub Actions workflow refreshes the data on a schedule and publishes
a static web dashboard to GitHub Pages.

Sources:

| Source | Coverage | Feed |
| ------ | -------- | ---- |
| **SOFA** | Apple | [`sofa.macadmins.io`](https://sofa.macadmins.io) — macOS/iOS security releases & actively-exploited CVEs |
| **MSRC CVRF v3.0** | Microsoft | [`api.msrc.microsoft.com`](https://github.com/Microsoft/MSRC-Microsoft-Security-Updates-API) — monthly "Patch Tuesday" updates, with Windows **client vs. server** breakdown and **hotpatch / B-release** servicing |
| **CISA KEV** | Third-party zero-days | [`cisa.gov`](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — actively-exploited vulns across Chrome, Firefox, Adobe, … with BOD 22-01 **due dates** |
| **NVD CVE API 2.0** | Third-party advisories | [`services.nvd.nist.gov`](https://nvd.nist.gov/developers/vulnerabilities) — recent high/critical CVEs per vendor (Adobe, Cisco, Fortinet, …) with CVSS |

The web UI is a **vulnerability-triage console**: a left rail of views
(Priority queue · Act now · Exploited/KEV · Windows · Apple · Third-party),
a clickable KPI bar, **risk-ranked** cards (priority score from exploitation,
CVSS, severity, recency and KEV deadline), and a detail drawer with full
remediation guidance and a CVE table.

Both feeds are normalized into a common model — a **patch** (a released
update) that fixes one or more **CVEs** — and stored in a local SQLite
database. You can then triage each patch through a tracking workflow
(`new → in_progress → applied / mitigated / wont_fix`), so your remediation
state survives feed refreshes.

> Built with the Python standard library only — no third-party runtime
> dependencies. Runs anywhere with Python 3.9+. The web dashboard is plain
> static HTML/CSS/JS — no framework, no build step.

## Web dashboard (auto-updating)

The [`.github/workflows/update-and-deploy.yml`](.github/workflows/update-and-deploy.yml)
workflow keeps a live dashboard fresh and deploys it to GitHub Pages:

| When | What |
| ---- | ---- |
| **Daily** (`06:17 UTC`) | Catches Apple (SOFA) releases and newly-exploited CVEs, which can land any day. |
| **Patch Tuesday** (`cron: 0 18 8-14 * 2`) | Microsoft ships monthly on the **second Tuesday**; this cron fires on the Tuesday whose date is 8–14, i.e. exactly Patch Tuesday, after the release. |

Each run fetches both feeds into a committed SQLite database (so every CVE's
`first_seen` date persists), regenerates `web/data.json`, commits it only when
something changed, and publishes `web/` to Pages. CVEs first seen within the
last 7 days are flagged **NEW**, so the dashboard surfaces CVEs released since
the previous run. Microsoft updates are labelled with their **Patch Tuesday**
date.

### Enabling it

1. In the repo: **Settings → Pages → Build and deployment → Source =
   GitHub Actions**.
2. The workflow has the needed `contents`/`pages`/`id-token` permissions; the
   default `GITHUB_TOKEN` is sufficient and its data commits don't retrigger
   the workflow (no loops).
3. Trigger a first run via **Actions → Update CVE data & deploy → Run
   workflow**, or just wait for the schedule.

### Build/preview the site locally

```bash
patch-tracker fetch                       # or: --file <saved-feed.json>
patch-tracker build-site --out web/data.json --new-days 7
python -m http.server -d web 8000         # open http://localhost:8000
```

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

# Generate the dashboard dataset
patch-tracker build-site --out web/data.json --new-days 7
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
  cli.py                 argparse CLI (fetch/list/show/cves/status/stats/
                         export/build-site)
  db.py                  SQLite store + queries (first_seen tracking)
  models.py              Patch / Cve dataclasses, severity ranking
  fetcher.py             stdlib HTTP JSON getter (allowlist-aware errors)
  report.py              text-table rendering
  site.py                build web/data.json from the database
  patch_tuesday.py       second-Tuesday math for Microsoft updates
  sources/
    apple_sofa.py        SOFA macOS/iOS feed parser
    microsoft_msrc.py    MSRC CVRF v3.0 parser
web/                     static dashboard (index.html, app.js, styles.css,
                         data.json)
.github/workflows/
  update-and-deploy.yml  daily + Patch Tuesday refresh, deploy to Pages
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
