function Get-IntuneAssignmentDrift {
    <#
    .SYNOPSIS
        Diff the current assignments against a snapshot (drift detection).

    .DESCRIPTION
        Compares the live tenant to a Backup-IntuneAssignment snapshot (or a
        baseline you keep in source control) and reports what changed per
        resource: targets Added (present now, not in the snapshot) and Removed
        (in the snapshot, gone now). Use it to catch unexpected changes since a
        backup, or to enforce a known-good baseline.

    .PARAMETER Path
        The JSON snapshot to compare against.

    .PARAMETER Area
        Limit to one or more areas.

    .PARAMETER Type
        Limit to one or more resource type keys.

    .PARAMETER ChangedOnly
        Only emit resources that actually drifted (default emits drift rows
        only anyway; this also suppresses the per-resource 'in sync' summary).

    .EXAMPLE
        Get-IntuneAssignmentDrift -Path baseline.json | Format-Table

        Everything that changed since the baseline.

    .EXAMPLE
        Get-IntuneAssignmentDrift -Path backup.json -Area Configuration |
            Where-Object Change -eq Removed

        Config-profile assignments that were removed since the backup.

    .OUTPUTS
        PSCustomObject: Area, ResourceType, Resource, Change (Added/Removed/Gone/New), Target.

    .LINK
        Backup-IntuneAssignment
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Area,
        [string[]]$Type,
        [switch]$ChangedOnly
    )
    $snap = Read-IaSnapshot -Path $Path
    $current = Get-IaInventory -Area $Area -Type $Type
    $curById = @{}; foreach ($it in $current) { $curById[$it.Id] = $it }
    $snapById = @{}; foreach ($r in $snap.resources) {
        if ($Area -and $r.area -notin $Area) { continue }
        if ($Type -and $r.resourceType -notin $Type) { continue }
        $snapById[$r.id] = $r
    }

    $allIds = @($snapById.Keys) + @($curById.Keys) | Select-Object -Unique
    foreach ($id in $allIds) {
        $s = $snapById[$id]; $c = $curById[$id]

        # rebuild target objects so we can match + display consistently
        $snapAssigns = if ($s) { @(ConvertFrom-IaAssignmentSnapshot -SnapResource $s) } else { @() }
        $curAssigns = if ($c) { @($c.Assignments) } else { @() }
        $snapMap = @{}; foreach ($a in $snapAssigns) { $snapMap[(Get-IaTargetMatchKey -Target $a.Target)] = $a }
        $curMap = @{}; foreach ($a in $curAssigns) { $curMap[(Get-IaTargetMatchKey -Target $a.Target)] = $a }

        $area = if ($c) { $c.Area } else { $s.area }
        $rtype = if ($c) { $c.ResourceType } else { $s.resourceType }
        $rname = if ($c) { $c.Name } else { $s.name }

        # added (in current, not snapshot)
        foreach ($k in $curMap.Keys) {
            if (-not $snapMap.ContainsKey($k)) {
                [pscustomobject]@{ Area = $area; ResourceType = $rtype; Resource = $rname
                    Change = if ($s) { 'Added' } else { 'New' }; Target = (Get-IaTargetDisplay -Target $curMap[$k].Target) }
            }
        }
        # removed (in snapshot, not current)
        foreach ($k in $snapMap.Keys) {
            if (-not $curMap.ContainsKey($k)) {
                [pscustomobject]@{ Area = $area; ResourceType = $rtype; Resource = $rname
                    Change = if ($c) { 'Removed' } else { 'Gone' }; Target = (Get-IaTargetDisplay -Target $snapMap[$k].Target) }
            }
        }
    }
}
