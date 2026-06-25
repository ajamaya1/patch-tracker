function Start-IntuneAssigner {
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
        Connect-IntuneAssigner -UseDeviceCode; Start-IntuneAssigner
    #>
    [CmdletBinding()]
    param([ValidateSet('green', 'amber')][string]$Theme = 'green')

    if (-not (Get-Command Read-SpectreSelection -ErrorAction SilentlyContinue)) {
        throw "The TUI needs PwshSpectreConsole. Install it with: Install-Module PwshSpectreConsole -Scope CurrentUser"
    }
    if (-not (Get-MgContext)) {
        Write-SpectreHost "[yellow]Not connected.[/] Starting device-code sign-in…"
        Connect-IntuneAssigner -UseDeviceCode | Out-Null
    }

    $accent = if ($Theme -eq 'amber') { 'orange1' } else { 'green' }
    $script:IaTuiInventory = $null

    function Get-IaTuiInventory {
        if ($null -eq $script:IaTuiInventory) {
            $script:IaTuiInventory = Invoke-SpectreCommandWithStatus -Spinner Dots -Title 'Reading Intune assignments…' -ScriptBlock {
                Get-IaInventory
            }
        }
        $script:IaTuiInventory
    }

    Clear-Host
    Write-SpectreFigletText -Text 'IntuneAssigner' -Color $accent
    $ctx = Get-MgContext
    Write-SpectreHost "[$accent]●[/] $($ctx.Account)  ·  tenant [grey]$($ctx.TenantId)[/]  ·  app [grey]$($ctx.AppName)[/]"
    Write-SpectreRule -Title 'retro intune assignment console' -Color $accent

    while ($true) {
        $choice = Read-SpectreSelection -Title "Choose an action" -Color $accent -Choices @(
            'View all assignments',
            'Group lookup (what is a group assigned to)',
            'Compare two groups',
            'What-if (user / device effective assignments)',
            'Mirror assignments (copy A -> B, pick which)',
            'Assign a group to many (pick which)',
            'Templates (capture / apply)',
            'Audit',
            'Export HTML report',
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
                'Audit'         { Invoke-IaTuiAudit -Accent $accent }
                'Export*'       { $p = Read-SpectreText -Question 'Output path' -DefaultAnswer 'intune-assignments.html'
                                  New-IaHtmlReport -Items (Get-IaTuiInventory) | Set-Content -Path $p -Encoding utf8
                                  Write-SpectreHost "[$accent]Wrote[/] $p" }
                'Refresh*'      { $script:IaTuiInventory = $null; Get-IaTuiInventory | Out-Null; Write-SpectreHost "[$accent]Refreshed.[/]" }
                'Quit'          { return }
            }
        } catch {
            Write-SpectreHost "[red]Error:[/] $($_.Exception.Message)"
        }
        if ($choice -ne 'Quit') { Read-SpectrePause | Out-Null }
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
