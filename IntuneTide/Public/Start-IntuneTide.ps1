function Start-IntuneTide {
    <#
    .SYNOPSIS
        Launch the interactive retro Spectre.Console TUI.
    .DESCRIPTION
        A keyboard-driven terminal UI: browse assignments, reverse-lookup a
        group, compare two groups, run what-if for a user/device, and — the
        headline — MIRROR a group's assignments onto another with a multi-select
        checklist so you choose exactly which ones (e.g. config profiles but not
        endpoint security). Cross-platform; needs the PwshSpectreConsole module.
    .EXAMPLE
        Connect-IntuneTide -UseDeviceCode; Start-IntuneTide
    #>
    [CmdletBinding()]
    param([ValidateSet('green', 'amber', 'lego', 'deepsea')][string]$Theme = 'green')

    if (-not (Get-Command Read-SpectreSelection -ErrorAction SilentlyContinue)) {
        throw "The TUI needs PwshSpectreConsole. Install it with: Install-Module PwshSpectreConsole -Scope CurrentUser"
    }
    if (-not (Get-MgContext)) {
        Write-SpectreHost "[yellow]Not connected.[/] Starting device-code sign-in…"
        Connect-IntuneTide -UseDeviceCode | Out-Null
    }

    $accent = switch ($Theme) { 'amber' { 'orange1' } 'lego' { 'yellow' } 'deepsea' { 'turquoise2' } default { 'green' } }
    $script:IaTuiInventory = $null
    $script:IaTuiShowLog = $true

    function Get-IaTuiInventory {
        if ($null -eq $script:IaTuiInventory) {
            if ($script:IaTuiShowLog) {
                # Live-stream each Graph call as the inventory loads.
                Write-SpectreHost "[grey]reading intune — live graph calls:[/]"
                Set-IaCallSink {
                    param($c)
                    $items = if ($c.Count) { " · $($c.Count) items" } else { '' }
                    Write-Host ("  → {0,-4} {1}  {2}ms{3}" -f $c.Method, $c.Uri, $c.Ms, $items)
                }
                try { $script:IaTuiInventory = Get-IaInventory } finally { Set-IaCallSink $null }
            } else {
                $script:IaTuiInventory = Invoke-SpectreCommandWithStatus -Spinner Dots -Title 'Reading Intune assignments…' -ScriptBlock {
                    Get-IaInventory
                }
            }
        }
        $script:IaTuiInventory
    }

    Clear-Host
    Write-SpectreFigletText -Text 'TIDE' -Color $accent
    $ctx = Get-MgContext
    $elev = try { if (Test-IaPrivileged) { "[green]● elevated[/]" } else { "[yellow]○ not elevated[/]" } } catch { '' }
    Write-SpectreHost "[$accent]●[/] $($ctx.Account)  ·  tenant [grey]$($ctx.TenantId)[/]  ·  $elev"
    Write-SpectreRule -Title 'TIDE · targeted intune deployment & endpoints' -Color $accent

    while ($true) {
        $choice = Read-SpectreSelection -Title "Choose an action" -Color $accent -Choices @(
            'View all assignments',
            'Group lookup (what is a group assigned to)',
            'Compare two groups',
            'What-if (user / device effective assignments)',
            'Mirror assignments (copy A -> B, pick which)',
            'Assign a group to many (pick which)',
            'Templates (capture / apply)',
            'Backup / Restore / Drift',
            'Reports (status · audit · approvals)',
            'Elevate (PIM) — activate an eligible role',
            'Audit',
            'Export report (HTML · Excel · Rich HTML)',
            'Toggle graph-call pane',
            'Refresh data',
            'Quit'
        )
        try {
            switch -Wildcard ($choice) {
                'View all*'   { Get-IaTuiInventory | ForEach-Object {
                                  [pscustomobject]@{ Area = $_.Area; Resource = $_.Name; Platform = $_.Platform
                                    AssignedTo = (($_.Assignments | ForEach-Object { Get-IaTargetDisplay -Target $_.Target }) -join '; ') } } |
                                  Format-SpectreTable -Color $accent }
                'Group lookup*' { Invoke-IaTuiGroupLookup -Accent $accent }
                'Compare*'      { Invoke-IaTuiCompare -Accent $accent }
                'What-if*'      { Invoke-IaTuiWhatIf -Accent $accent }
                'Mirror*'       { Invoke-IaTuiMirror -Accent $accent }
                'Assign a group*' { Invoke-IaTuiBulkAssign -Accent $accent }
                'Templates*'    { Invoke-IaTuiTemplates -Accent $accent }
                'Backup*'       { Invoke-IaTuiBackup -Accent $accent }
                'Reports*'      { Invoke-IaTuiReports -Accent $accent }
                'Elevate*'      { Invoke-IaTuiElevate -Accent $accent }
                'Audit'         { Invoke-IaTuiAudit -Accent $accent }
                'Export*'       { Invoke-IaTuiExport -Accent $accent }
                'Refresh*'      { $script:IaTuiInventory = $null; Get-IaTuiInventory | Out-Null; Write-SpectreHost "[$accent]Refreshed.[/]" }
                'Toggle graph*' { $script:IaTuiShowLog = -not $script:IaTuiShowLog
                                  Write-SpectreHost "graph-call pane: $(if ($script:IaTuiShowLog) { "[green]on[/]" } else { "[grey]off[/]" })" }
                'Quit'          { return }
            }
        } catch {
            Write-SpectreHost "[red]Error:[/] $($_.Exception.Message)"
        }
        if ($choice -ne 'Quit') {
            if ($script:IaTuiShowLog) { Show-IaTuiCallLog -Accent $accent }
            Read-SpectrePause | Out-Null
        }
    }
}

function Invoke-IaTuiGroupLookup {
    param([string]$Accent)
    $name = Read-SpectreText -Question 'Group name or id'
    $g = Resolve-IaGroup -Value $name
    $hits = foreach ($it in (Get-IaTuiInventory)) {
        foreach ($e in (Get-IaItemGroupEdges -Item $it -GroupId $g.Id)) {
            [pscustomobject]@{ Area = $it.Area; Resource = $it.Name
                Mode = if ($e.Target.IsExclude) { 'EXCLUDE' } else { 'include' }; Intent = $e.Intent }
        }
    }
    Write-SpectreHost "[$Accent]$($g.DisplayName)[/] is assigned to [$Accent]$(@($hits).Count)[/] resource(s)"
    if ($hits) { $hits | Format-SpectreTable -Color $Accent }
}

function Invoke-IaTuiCompare {
    param([string]$Accent)
    $a = Resolve-IaGroup -Value (Read-SpectreText -Question 'Group A')
    $b = Resolve-IaGroup -Value (Read-SpectreText -Question 'Group B')
    $rows = foreach ($it in (Get-IaTuiInventory)) {
        $am = Get-IaItemGroupMode -Item $it -GroupId $a.Id
        $bm = Get-IaItemGroupMode -Item $it -GroupId $b.Id
        if ($am -eq 'none' -and $bm -eq 'none') { continue }
        $rel = if ($am -ne 'none' -and $bm -eq 'none') { 'OnlyA' }
               elseif ($bm -ne 'none' -and $am -eq 'none') { 'OnlyB' }
               elseif (($am -eq 'include' -and $bm -eq 'exclude') -or ($am -eq 'exclude' -and $bm -eq 'include')) { 'Conflict' }
               else { 'Both' }
        [pscustomobject]@{ Area = $it.Area; Resource = $it.Name; Relationship = $rel; A = $am; B = $bm }
    }
    Write-SpectreHost "A = [$Accent]$($a.DisplayName)[/]   B = [$Accent]$($b.DisplayName)[/]"
    $rows | Format-SpectreTable -Color $Accent
}

function Invoke-IaTuiWhatIf {
    param([string]$Accent)
    $kind = Read-SpectreSelection -Title 'Subject type' -Choices @('user', 'device') -Color $Accent
    $val = Read-SpectreText -Question "$kind (UPN/name or id)"
    $rows = if ($kind -eq 'user') { Get-IntuneEffectiveAssignment -User $val }
            else { Get-IntuneEffectiveAssignment -Device $val }
    $rows | Format-SpectreTable -Color $Accent
}

function Invoke-IaTuiMirror {
    param([string]$Accent)
    $src = Resolve-IaGroup -Value (Read-SpectreText -Question 'Source group (copy FROM)')
    $items = Get-IaTuiInventory
    $cands = Get-IaCopyCandidates -Items $items -SrcId $src.Id
    if (-not $cands) { Write-SpectreHost "[yellow]$($src.DisplayName) has no assignments to mirror.[/]"; return }

    # Build a unique label per candidate so the multi-select maps back cleanly.
    $map = @{}; $i = 0
    $labels = foreach ($c in $cands) { $i++; $lbl = "$i. [$($c.Area)] $($c.Name)"; $map[$lbl] = $c.Id; $lbl }
    $picked = Read-SpectreMultiSelection -Title "Select what to mirror from [$Accent]$($src.DisplayName)[/]" `
        -Choices $labels -Color $Accent
    if (-not $picked) { Write-SpectreHost '[yellow]Nothing selected.[/]'; return }
    $ids = @($picked | ForEach-Object { $map[$_] })

    $dst = Resolve-IaGroup -Value (Read-SpectreText -Question 'Destination group (copy TO)')
    $confirm = Read-SpectreSelection -Title "Apply $($ids.Count) assignment(s) to [$Accent]$($dst.DisplayName)[/]?" `
        -Choices @('Preview only (no changes)', 'Apply now') -Color $Accent
    $commit = $confirm -eq 'Apply now'

    $plans = Invoke-IaCopy -Items $items -SrcId $src.Id -DstId $dst.Id -DstName $dst.DisplayName `
        -IncludeIds $ids -Commit:$commit
    if (-not $plans) { Write-SpectreHost '[yellow]Nothing to change (already assigned?).[/]'; return }
    $plans | ForEach-Object {
        [pscustomobject]@{ Status = if ($commit) { if ($_.Applied) { 'OK' } else { 'FAILED' } } else { 'PREVIEW' }
            Area = $_.Area; Resource = $_.ResourceName; Added = ($_.Added -join '; '); Error = $_.Error }
    } | Format-SpectreTable -Color $Accent
    if (-not $commit) { Write-SpectreHost "[grey]Preview only — re-run and choose 'Apply now' to write.[/]" }
}

function Invoke-IaTuiAudit {
    param([string]$Accent)
    $a = Invoke-SpectreCommandWithStatus -Spinner Dots -Title 'Auditing…' -ScriptBlock {
        Get-IntuneAssignmentAudit
    }
    Write-SpectreHost "Resources [$Accent]$($a.ResourceCount)[/]  ·  assigned [$Accent]$($a.AssignedCount)[/]  ·  unassigned [$Accent]$($a.UnassignedCount)[/]  ·  edges [$Accent]$($a.EdgeCount)[/]"
    $a.ByArea | Format-SpectreTable -Color $Accent
    if ($a.TopGroups) { Write-SpectreHost "[$Accent]Most-assigned groups[/]"; $a.TopGroups | Format-SpectreTable -Color $Accent }
}

function Invoke-IaTuiBulkAssign {
    param([string]$Accent)
    $g = Resolve-IaGroup -Value (Read-SpectreText -Question 'Group to assign')
    $areas = @('All areas') + (@(Get-IaResourceRegistry | ForEach-Object Area | Select-Object -Unique | Sort-Object))
    $area = Read-SpectreSelection -Title 'Which area?' -Choices $areas -Color $Accent

    $items = Get-IaTuiInventory
    $scoped = if ($area -eq 'All areas') { $items } else { @($items | Where-Object Area -eq $area) }
    if (-not $scoped) { Write-SpectreHost "[yellow]No resources in $area.[/]"; return }

    # Apps take an install intent.
    $intent = $null
    if ($area -eq 'Apps' -or ($scoped | Where-Object { (Find-IaResourceType -Key $_.ResourceType).HasIntent })) {
        $intent = Read-SpectreSelection -Title 'Install intent (apps)' -Color $Accent `
            -Choices @('required', 'available', 'uninstall', 'availableWithoutEnrollment', '(none / non-app)')
        if ($intent -eq '(none / non-app)') { $intent = $null }
    }
    $modeChoice = Read-SpectreSelection -Title 'Assignment mode' -Choices @('include', 'exclude (block)') -Color $Accent
    $exclude = $modeChoice -like 'exclude*'

    # Optional assignment filter (include/exclude).
    $filterId = $null; $filterType = 'include'
    $filters = Get-IaFilterList
    if ($filters) {
        $fchoice = Read-SpectreSelection -Title 'Assignment filter' -Color $Accent `
            -Choices (@('(no filter)') + @($filters | ForEach-Object Name))
        if ($fchoice -ne '(no filter)') {
            $filterId = ($filters | Where-Object Name -eq $fchoice | Select-Object -First 1).Id
            $filterType = Read-SpectreSelection -Title "Filter mode for '$fchoice'" -Choices @('include', 'exclude') -Color $Accent
        }
    }

    $map = @{}; $i = 0
    $labels = foreach ($it in ($scoped | Sort-Object Area, Name)) {
        $i++; $lbl = "$i. [$($it.Area)] $($it.Name)"; $map[$lbl] = $it; $lbl
    }
    $picked = Read-SpectreMultiSelection -Title "Select resources to assign [$Accent]$($g.DisplayName)[/]" `
        -Choices $labels -Color $Accent -PageSize 18
    if (-not $picked) { Write-SpectreHost '[yellow]Nothing selected.[/]'; return }
    $sel = @($picked | ForEach-Object { $map[$_] })

    $verb = if ($exclude) { 'EXCLUDE' } else { 'assign' }
    $confirm = Read-SpectreSelection -Color $Accent `
        -Title "$verb [$Accent]$($g.DisplayName)[/] on $($sel.Count) resource(s)?" `
        -Choices @('Preview only (no changes)', 'Apply now')
    $commit = $confirm -eq 'Apply now'

    $plans = Invoke-IaBulkAssign -Items $sel -GroupId $g.Id -GroupName $g.DisplayName `
        -Exclude:$exclude -Intent $intent -FilterId $filterId -FilterType $filterType -Commit:$commit
    $plans | ForEach-Object {
        [pscustomobject]@{
            Status = if ($_.Skipped) { 'SKIP' } elseif (-not $commit) { 'PREVIEW' } elseif ($_.Applied) { 'OK' } else { 'FAILED' }
            Area = $_.Area; Resource = $_.ResourceName
            Detail = if ($_.Skipped) { $_.Skipped } else { ($_.Added -join '; ') }
        }
    } | Format-SpectreTable -Color $Accent
    if ($commit) { $script:IaTuiInventory = $null }  # state changed; force refresh next time
    else { Write-SpectreHost "[grey]Preview only — choose 'Apply now' to write.[/]" }
}

function Invoke-IaTuiTemplates {
    param([string]$Accent)
    $action = Read-SpectreSelection -Title 'Templates' -Color $Accent -Choices @(
        'Capture a group as a template (save to file)',
        'Apply a template file to a group'
    )
    if ($action -like 'Capture*') {
        $g = Resolve-IaGroup -Value (Read-SpectreText -Question 'Group to capture')
        $name = Read-SpectreText -Question 'Template name' -DefaultAnswer 'baseline'
        $path = Read-SpectreText -Question 'Save to path' -DefaultAnswer "$name.json"
        $tmpl = New-IaTemplateFromGroup -Items (Get-IaTuiInventory) -GroupId $g.Id -Name $name
        $tmpl | ConvertTo-Json -Depth 8 | Set-Content -Path $path -Encoding utf8
        Write-SpectreHost "[$Accent]Saved[/] template '$name' with [$Accent]$($tmpl.resources.Count)[/] resource(s) -> $path"
    }
    else {
        $path = Read-SpectreText -Question 'Template file path'
        if (-not (Test-Path $path)) { Write-SpectreHost "[red]Not found:[/] $path"; return }
        $tmpl = Get-Content $path -Raw | ConvertFrom-Json
        $g = Resolve-IaGroup -Value (Read-SpectreText -Question 'Device group to stamp on')
        $keys = @($tmpl.resources | ForEach-Object resource_type | Select-Object -Unique)
        $items = Get-IaInventory -Type $keys
        $confirm = Read-SpectreSelection -Color $Accent `
            -Title "Apply template '$($tmpl.name)' ($($tmpl.resources.Count) resources) to [$Accent]$($g.DisplayName)[/]?" `
            -Choices @('Preview only (no changes)', 'Apply now')
        $commit = $confirm -eq 'Apply now'
        $plans = Invoke-IaTemplateApply -Template $tmpl -Items $items -GroupId $g.Id -GroupName $g.DisplayName -Commit:$commit
        $plans | ForEach-Object {
            [pscustomobject]@{
                Status = if ($_.Skipped) { 'SKIP' } elseif (-not $commit) { 'PREVIEW' } elseif ($_.Applied) { 'OK' } else { 'FAILED' }
                Area = $_.Area; Resource = $_.ResourceName; Detail = if ($_.Skipped) { $_.Skipped } else { ($_.Added -join '; ') }
            }
        } | Format-SpectreTable -Color $Accent
        if ($commit) { $script:IaTuiInventory = $null }
    }
}

function Invoke-IaTuiElevate {
    param([string]$Accent)
    $eligible = Get-IntuneEligibleRole
    if (-not $eligible) {
        Write-SpectreHost '[yellow]You have no PIM-eligible roles to activate (or this is an app-only sign-in).[/]'
        $active = Get-IntuneActiveRole
        if ($active) { Write-SpectreHost 'Currently active:'; $active | Format-SpectreTable -Color $Accent }
        return
    }
    $role = Read-SpectreSelection -Title 'Activate which eligible role?' -Color $Accent `
        -Choices @($eligible | ForEach-Object Role)
    $just = Read-SpectreText -Question 'Justification'
    $dur = Read-SpectreText -Question 'Duration (e.g. 2h, 30m, 8h)' -DefaultAnswer '2h'
    $confirm = Read-SpectreSelection -Title "Activate [$Accent]$role[/] for $dur?" `
        -Choices @('Yes, activate now', 'Cancel') -Color $Accent
    if ($confirm -notlike 'Yes*') { Write-SpectreHost '[grey]Cancelled.[/]'; return }

    $res = Enable-IntuneAdminRole -Role $role -Justification $just -Duration $dur -Confirm:$false
    Write-SpectreHost "[$Accent]$($res.Role)[/] → status [$Accent]$($res.Status)[/] (expires after $($res.Duration))"
    if ($res.Status -in 'PendingApproval', 'PendingProvisioning') {
        Write-SpectreHost '[yellow]Activation needs approval / is provisioning — re-check with Get-IntuneActiveRole.[/]'
    }
    Get-IntuneActiveRole | Format-SpectreTable -Color $Accent
}

function Show-IaTuiCallLog {
    # The bottom "graph calls" pane: the last several Graph requests, status-colored.
    param([string]$Accent, [int]$Tail = 12)
    $calls = Get-IaCallLogEntries | Select-Object -Last $Tail
    if (-not $calls) { return }
    $rows = foreach ($c in $calls) {
        [pscustomobject]@{
            Time   = $c.Time.ToString('HH:mm:ss')
            Method = $c.Method
            Endpoint = $c.Uri
            Status = $c.Status
            Ms     = $c.Ms
            Items  = $c.Count
        }
    }
    $okCount = @($calls | Where-Object { $_.Status -ge 200 -and $_.Status -lt 300 }).Count
    Write-SpectreHost "[grey]── graph calls ── last $($rows.Count) · $okCount ok · session total $((Get-IaCallLogEntries).Count) ──[/]"
    $rows | Format-SpectreTable -Color $Accent
}

function Invoke-IaTuiReports {
    # Reports submenu — surfaces the status / audit / approval / any-report cmdlets.
    param([string]$Accent)
    $pick = Read-SpectreSelection -Title 'Reports' -Color $Accent -Choices @(
        'App install status (device / user)',
        'Configuration profile status',
        'Compliance status',
        'Deployment summary (success / fail, by group)',
        'Audit log (who changed what)',
        'Multi Admin Approval requests',
        'PIM activations',
        'Run any Intune report',
        'Back'
    )
    switch -Wildcard ($pick) {
        'App install*' {
            $app = Read-SpectreText -Question 'App name (or id)'
            $by = Read-SpectreSelection -Title 'Pivot by' -Choices @('Device', 'User') -Color $Accent
            Invoke-SpectreCommandWithStatus -Spinner Dots -Title "Querying $app…" -ScriptBlock {
                Get-IntuneAppInstallStatus -App $using:app -By $using:by
            } | Format-SpectreTable -Color $Accent
        }
        'Configuration*' {
            $p = Read-SpectreText -Question 'Configuration profile name (or id)'
            Get-IntuneConfigurationStatus -Profile $p | Format-SpectreTable -Color $Accent
        }
        'Compliance*' {
            $mode = Read-SpectreSelection -Title 'Compliance by' -Choices @('Tenant summary', 'Policy', 'Device') -Color $Accent
            $rows = switch -Wildcard ($mode) {
                'Policy'  { Get-IntuneComplianceStatus -Policy (Read-SpectreText -Question 'Policy name') }
                'Device'  { Get-IntuneComplianceStatus -Device (Read-SpectreText -Question 'Device name') }
                default   { Get-IntuneComplianceStatus }
            }
            $rows | Format-SpectreTable -Color $Accent
        }
        'Deployment*' {
            $grp = Read-SpectreText -Question 'Scope to group (blank = all)' -DefaultAnswer ''
            Invoke-SpectreCommandWithStatus -Spinner Dots -Title 'Rolling up deployment health…' -ScriptBlock {
                if ($using:grp) { Get-IntuneDeploymentSummary -Group $using:grp } else { Get-IntuneDeploymentSummary }
            } | Format-SpectreTable -Color $Accent
        }
        'Audit*' {
            $since = Read-SpectreText -Question 'Since (e.g. 7d, 24h)' -DefaultAnswer '7d'
            $act = Read-SpectreText -Question 'Activity contains (blank = any)' -DefaultAnswer ''
            $p = @{ Since = $since }; if ($act) { $p.Activity = $act }
            Get-IntuneAuditLog @p | Select-Object -First 50 | Format-SpectreTable -Color $Accent
        }
        'Multi Admin*' {
            Get-IntuneApprovalRequest | Format-SpectreTable -Color $Accent
        }
        'PIM*' {
            Get-IntunePimActivation | Format-SpectreTable -Color $Accent
        }
        'Run any*' {
            $name = Read-SpectreSelection -Title 'Pick a report' -Color $Accent `
                -Choices (@(Get-IntuneReportCatalog | ForEach-Object Name) + 'Other (type a name)')
            if ($name -like 'Other*') { $name = Read-SpectreText -Question 'Report name' }
            Invoke-SpectreCommandWithStatus -Spinner Dots -Title "Running $name…" -ScriptBlock {
                Export-IntuneReport -Name $using:name
            } | Select-Object -First 100 | Format-SpectreTable -Color $Accent
        }
        default { return }
    }
}

function Invoke-IaTuiBackup {
    param([string]$Accent)
    $pick = Read-SpectreSelection -Title 'Backup / Restore / Drift' -Color $Accent -Choices @(
        'Backup all assignments to a file',
        'Drift — compare current vs a snapshot',
        'Restore from a snapshot',
        'Back'
    )
    switch -Wildcard ($pick) {
        'Backup*' {
            $p = Read-SpectreText -Question 'Save snapshot to' -DefaultAnswer 'intune-assignments.json'
            $snap = Backup-IntuneAssignment -Path $p
            Write-SpectreHost "[$Accent]Backed up[/] $($snap.count) resource(s) → $p"
        }
        'Drift*' {
            $p = Read-SpectreText -Question 'Snapshot file to compare against'
            $d = @(Get-IntuneAssignmentDrift -Path $p)
            if (-not $d) { Write-SpectreHost "[$Accent]No drift — current state matches the snapshot.[/]"; return }
            Write-SpectreHost "[$Accent]$($d.Count)[/] drifted assignment target(s):"
            $d | Format-SpectreTable -Color $Accent
        }
        'Restore*' {
            $p = Read-SpectreText -Question 'Snapshot file to restore'
            $mode = Read-SpectreSelection -Title 'Restore mode' -Color $Accent -Choices @('Preview only (no changes)', 'Apply now')
            $plans = if ($mode -like 'Apply*') { Restore-IntuneAssignment -Path $p -Confirm:$false } else { Restore-IntuneAssignment -Path $p -WhatIf }
            @($plans) | ForEach-Object {
                [pscustomobject]@{
                    Status = if ($_.Skipped) { 'SKIP' } elseif ($_.Error) { 'FAIL' } elseif ($_.Applied) { 'OK' } else { 'PREVIEW' }
                    Area = $_.Area; Resource = $_.ResourceName
                    Detail = if ($_.Skipped) { $_.Skipped } elseif ($_.Error) { $_.Error } else { ($_.Added -join '; ') }
                }
            } | Format-SpectreTable -Color $Accent
            if ($mode -like 'Apply*') { $script:IaTuiInventory = $null }
        }
        default { return }
    }
}

function Invoke-IaTuiExport {
    param([string]$Accent)
    $fmt = Read-SpectreSelection -Title 'Export format' -Color $Accent -Choices @(
        'Built-in HTML (themed, no dependencies)',
        'Excel workbook (ImportExcel)',
        'Rich interactive HTML (PSWriteHTML)'
    )
    switch -Wildcard ($fmt) {
        'Built-in*' {
            $p = Read-SpectreText -Question 'Output path' -DefaultAnswer 'intune-assignments.html'
            New-IaHtmlReport -Items (Get-IaTuiInventory) | Set-Content -Path $p -Encoding utf8
            Write-SpectreHost "[$Accent]Wrote[/] $p"
        }
        'Excel*' {
            if (-not (Get-Command Export-Excel -ErrorAction SilentlyContinue)) {
                Write-SpectreHost "[yellow]ImportExcel not installed.[/] Install-Module ImportExcel -Scope CurrentUser"; return
            }
            $p = Read-SpectreText -Question 'Output path' -DefaultAnswer 'intune-assignments.xlsx'
            Get-IntuneAssignment -Flat | Export-IntuneExcel -Path $p -WorksheetName Assignments -Title 'Intune assignments'
            Write-SpectreHost "[$Accent]Wrote[/] $p"
        }
        'Rich*' {
            if (-not (Get-Command New-HTML -ErrorAction SilentlyContinue)) {
                Write-SpectreHost "[yellow]PSWriteHTML not installed.[/] Install-Module PSWriteHTML -Scope CurrentUser"; return
            }
            $p = Read-SpectreText -Question 'Output path' -DefaultAnswer 'intune-assignments-rich.html'
            Export-IntuneHtmlReport -Path $p
            Write-SpectreHost "[$Accent]Wrote[/] $p"
        }
    }
}
