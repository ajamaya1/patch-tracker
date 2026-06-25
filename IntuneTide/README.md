# TIDE — Intune assignments & reporting (PowerShell)

A cross-platform **PowerShell module + retro Spectre.Console TUI** for inspecting
and managing Microsoft Intune assignments across every assignable area. Runs on
**macOS, Windows and Linux** under `pwsh` (PowerShell 7) using the Microsoft
Graph PowerShell SDK.

## What it does

* **See everything** — list all assignments across configuration, compliance,
  apps, app config/protection, scripts, remediations, Windows Update rings,
  endpoint security, enrollment, Cloud PC and scope tags, with group GUIDs
  resolved to names, include/exclude, filters, app intent and settings.
* **Reverse lookup** — what is *this group* assigned to.
* **Compare** two groups; **what-if** the effective assignments for a user or
  device (resolving transitive group membership; exclusions win).
* **Copy / mirror** a group's assignments onto another — *all or a chosen
  subset* (e.g. mirror config profiles but not endpoint security).
* **Bulk-assign**, reusable **templates**, **audit** (incl. empty-group
  detection), and HTML/CSV/JSON **reports**.
* An interactive **retro terminal UI** with a multi-select checklist for the
  mirror workflow.

## Install prerequisites

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser   # required
Install-Module PwshSpectreConsole            -Scope CurrentUser   # for the TUI
```

## Quick start

```powershell
Import-Module ./IntuneTide/IntuneTide.psd1

# Sign in (device code is handy on a Mac / over SSH)
Connect-IntuneTide -UseDeviceCode
# ...or app-only for automation:
# Connect-IntuneTide -TenantId contoso.com -ClientId <id> -ClientSecret <secret>

Get-IntuneAssignment -AssignedOnly | Format-Table Area, Name, AssignedTo
Get-IntuneGroupAssignment -Group "All Workstations"
Compare-IntuneAssignment -GroupA Pilot -GroupB Prod | Where-Object Relationship -eq OnlyA
Get-IntuneEffectiveAssignment -User jdoe@contoso.com | Where-Object Effective

# Mirror — only some of them. -WhatIf previews; drop it to apply.
Copy-IntuneAssignment -FromGroup Pilot -ToGroup Prod -Area Configuration -WhatIf
Copy-IntuneAssignment -FromGroup Pilot -ToGroup Prod -NameLike Defender

# Templates
Export-IntuneAssignmentTemplate -Group "Gold Build" -Name gold -Path gold.json
Import-IntuneAssignmentTemplate -Path gold.json -Group "New Store Devices" -WhatIf

# Audit + reports
(Get-IntuneAssignmentAudit -CheckEmptyGroups).EmptyGroups
Export-IntuneAssignmentReport -Format Html -Path assignments.html

# The interactive retro TUI (pick what to mirror with a checklist)
Start-IntuneTide            # green phosphor
Start-IntuneTide -Theme amber
```

## Selective mirror (your "config profiles but not endpoint security")

Three ways, all preserving include/exclude, app intent + settings, remediation
schedules and filters:

```powershell
Copy-IntuneAssignment -FromGroup A -ToGroup B -Area Configuration      # whole area(s)
Copy-IntuneAssignment -FromGroup A -ToGroup B -NameLike "Defender"     # by name
Copy-IntuneAssignment -FromGroup A -ToGroup B -Include "Win Baseline","Edge"  # explicit list
Start-IntuneTide   # → "Mirror assignments" → tick exactly what you want
```

Every write goes through the resource's `/assign` action, which replaces the
assignment list — the module always read-merges-writes so existing targets are
never clobbered, and identical targets are skipped.

## Graph permissions

Read needs `DeviceManagementConfiguration.Read.All`,
`DeviceManagementApps.Read.All`, `DeviceManagementServiceConfig.Read.All`,
`Group.Read.All`, `Directory.Read.All`. Writes need the matching
`*.ReadWrite.All` scopes (the default `Connect-IntuneTide` scope set
requests these). A 403 on one area is treated as "no permission / not licensed"
for that area and skipped — the rest of the sweep continues.

## Cmdlets

| Cmdlet | Purpose |
| ------ | ------- |
| `Connect-IntuneTide` | Sign in (interactive / device-code / app-only) |
| `Get-IntuneAssignment` | List all assignments (`-Flat` for one row per edge) |
| `Get-IntuneGroupAssignment` | Reverse lookup for a group |
| `Compare-IntuneAssignment` | Diff two groups |
| `Get-IntuneEffectiveAssignment` | What-if for a user / device |
| `Copy-IntuneAssignment` | Copy / selectively mirror group → group |
| `Add-IntuneBulkAssignment` | Assign one group to many resources |
| `Export-/Import-IntuneAssignmentTemplate` | Save / apply a template |
| `Get-IntuneAssignmentAudit` | Tenant audit (+ empty groups) |
| `Export-IntuneAssignmentReport` | HTML / CSV / JSON report |
| `Start-IntuneTide` | Interactive retro TUI |

## Tests

```powershell
Invoke-Pester ./IntuneTide/IntuneTide.Tests.ps1
```

Graph is mocked at the `Invoke-IaRequest` seam, so the suite runs fully offline.
