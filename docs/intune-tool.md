# intune-tool

A dependency-free CLI + library for **inspecting and managing Microsoft Intune
assignments** across every assignable area, built on the Microsoft Graph
`beta` endpoint. It answers the two questions the Intune portal makes slow —
*"what is assigned, and to which groups?"* and *"what is this group assigned
to?"* — and adds the power tools built on top: copy, bulk-assign, templates,
export and audit.

> Same engineering philosophy as the rest of this repo: standard library only,
> every network call behind an injectable transport, fully unit-tested offline.

## What it covers

19 resource types across 9 areas (run `intune-tool areas` for the live list):

| Area | Resource types |
| ---- | -------------- |
| Configuration | Settings catalog, device configuration profiles, ADMX templates |
| Compliance | Compliance policies |
| Scripts | Platform/PowerShell scripts, macOS shell scripts |
| Remediations | Health scripts (proactive remediations) |
| Windows Update | Update rings, feature / quality / driver update profiles |
| Endpoint security | Security baselines / intents |
| Enrollment | Enrollment configurations |
| Apps | Applications, app configuration policies, managed-app configs |
| App protection | iOS / Android / Windows app protection policies |

Each assignment is resolved to: real **group display names**, include vs.
**exclude** intent, **assignment filters** (with include/exclude mode), app
**install intent**, and per-assignment **settings/notifications**. Virtual
targets (*All Users* / *All Devices*) are surfaced too.

## Authentication

Three ways in, in order of convenience:

1. **An existing bearer token** — fastest for ad-hoc use:
   ```bash
   export INTUNE_TOKEN="$(az account get-access-token \
     --resource https://graph.microsoft.com --query accessToken -o tsv)"
   intune-tool list
   ```
2. **Device-code sign-in (delegated)** — interactive, uses *your* Intune RBAC,
   no app secret. Defaults to the public "Microsoft Graph Command Line Tools"
   client:
   ```bash
   export INTUNE_TENANT="contoso.onmicrosoft.com"
   intune-tool list        # prints a URL + code to approve in a browser
   ```
3. **App registration (client credentials)** — unattended, for scheduled
   audits/reports:
   ```bash
   export INTUNE_TENANT=... INTUNE_TOOL_CLIENT_ID=... INTUNE_CLIENT_SECRET=...
   intune-tool audit --out audit.txt
   ```

Delegated tokens (and their refresh token) are cached at
`~/.intune-tool/token-cache.json` (mode `0600`), so you sign in once per
session window.

### Graph permissions

Read needs `DeviceManagementConfiguration.Read.All`,
`DeviceManagementApps.Read.All`, `DeviceManagementServiceConfig.Read.All`,
`Group.Read.All`. Writes (`copy`, `bulk-assign`, `template apply`) need the
matching `*.ReadWrite.All` scopes. A 403 on one area is treated as "no
permission / not licensed" for that area and skipped — the rest of the sweep
continues.

## Commands

```bash
intune-tool areas                         # list inspectable areas/types

# See everything, groups resolved
intune-tool list                          # all areas
intune-tool list --area Apps --assigned-only
intune-tool list --type configurationPolicies --output csv --out assignments.csv
intune-tool list --platform windows --output json

# Reverse lookup: what is a group assigned to?
intune-tool group "All Workstations"
intune-tool group <group-guid> --output json

# Copy every assignment from one group to another (preserves include/exclude,
# app intent + settings, and filters)
intune-tool copy --from "Pilot Ring" --to "Production Ring" --dry-run
intune-tool copy --from <guid-a> --to <guid-b>

# Bulk-assign one group to many resources
intune-tool bulk-assign --group "All Macs" --area Compliance --intent required
intune-tool bulk-assign --group "Kiosks" --type mobileApps \
  --name-contains "Edge" --filter "Corp Windows" --filter-type include
intune-tool bulk-assign --group "Legacy" --area Configuration --exclude

# Templates: capture a group's assignments, then stamp new device groups onto them
intune-tool template export --group "Gold Build" --name gold --out gold.json
intune-tool template show --file gold.json
intune-tool template apply --file gold.json --group "New Store Devices" --dry-run

# Tenant-wide audit report (for change reviews / compliance evidence)
intune-tool audit --out audit.txt
```

### Group arguments

`--group`, `--from`, `--to` accept either a **GUID** or an exact **display
name**. Ambiguous names (two groups same name) error out and list the
candidate GUIDs.

### Write safety

Writes apply immediately by default. Pass `--dry-run` to any write command
(`copy`, `bulk-assign`, `template apply`) to preview the exact change set
without sending anything to Graph. Every write goes through the resource's
`/assign` action, which *replaces* the assignment list — the tool always
read-merges-writes so existing targets are never clobbered, and identical
targets are skipped as no-ops.

## Templates

A template is portable JSON describing a set of resources (the "thing" that
gets assigned). Build one from a known-good group, commit it, and reuse it to
onboard new device groups consistently:

```json
{
  "name": "gold",
  "description": "Standard Windows build",
  "version": 1,
  "resources": [
    {"resource_type": "configurationPolicies", "name": "Win Baseline", "id": "..."},
    {"resource_type": "deviceCompliancePolicies", "name": "Win Compliance", "id": "..."},
    {"resource_type": "mobileApps", "name": "Company Portal", "intent": "required"}
  ]
}
```

`template apply` resolves each resource by `id` (falling back to
`resource_type` + `name`), then adds the target group to it. Resources not
found in the tenant are reported as skipped, not failed.

## Library use

```python
from intune_tool.auth import Authenticator
from intune_tool.graph import GraphClient
from intune_tool.assignments import AssignmentEngine

client = GraphClient(Authenticator.from_env().token)
engine = AssignmentEngine(client)

items = engine.enumerate(only_assigned=True)          # all areas, resolved
hits = engine.by_group(group_id, items)               # reverse lookup
engine.copy_group(src_id, dst_id, items)              # copy
```

Inject a fake `transport=` into `GraphClient` to run the whole engine offline
— see `tests/intune_fake.py`.
