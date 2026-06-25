function Restore-IntuneAssignment {
    <#
    .SYNOPSIS
        Re-apply an assignment snapshot, restoring resources to its state.

    .DESCRIPTION
        For each resource in the snapshot, sets its assignment list back to the
        snapshot via the /assign action (which replaces the whole set). This is
        a *restore to a point in time* — targets added since the backup are
        removed and removed ones are re-added. Always preview with -WhatIf
        first. Resources no longer present in the tenant are reported and
        skipped.

    .PARAMETER Path
        The JSON snapshot from Backup-IntuneAssignment.

    .PARAMETER Area
        Restrict the restore to one or more areas.

    .PARAMETER Type
        Restrict to one or more resource type keys.

    .PARAMETER DiffOnly
        Skip resources whose current assignments already match the snapshot.

    .EXAMPLE
        Restore-IntuneAssignment -Path backup.json -WhatIf

        Preview exactly what restoring would change.

    .EXAMPLE
        Restore-IntuneAssignment -Path backup.json -Area Apps -DiffOnly

        Restore only the app resources that have drifted from the snapshot.

    .OUTPUTS
        Change-plan objects (Area, ResourceName, Added/Skipped/Applied/Error).

    .LINK
        Backup-IntuneAssignment
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Area,
        [string[]]$Type,
        [switch]$DiffOnly
    )
    $snap = Read-IaSnapshot -Path $Path
    $keys = @($snap.resources | ForEach-Object resourceType | Select-Object -Unique)
    $current = Get-IaInventory -Type $keys
    $byId = @{}; foreach ($it in $current) { $byId[$it.Id] = $it }

    foreach ($r in $snap.resources) {
        if ($Area -and $r.area -notin $Area) { continue }
        if ($Type -and $r.resourceType -notin $Type) { continue }
        $it = $byId[$r.id]
        if (-not $it) {
            New-IaChangePlan -Item ([pscustomobject]@{ Area = $r.area; ResourceType = $r.resourceType; Name = $r.name; Id = $r.id }) `
                -Skipped 'resource no longer exists'
            continue
        }
        $desired = @(ConvertFrom-IaAssignmentSnapshot -SnapResource $r)
        $curKeys = @($it.Assignments | ForEach-Object { Get-IaTargetMatchKey -Target $_.Target })
        $desKeys = @($desired | ForEach-Object { Get-IaTargetMatchKey -Target $_.Target })
        $same = (@($curKeys | Where-Object { $_ -notin $desKeys }).Count -eq 0) -and
                (@($desKeys | Where-Object { $_ -notin $curKeys }).Count -eq 0)
        if ($DiffOnly -and $same) { New-IaChangePlan -Item $it -Skipped 'already matches snapshot'; continue }

        if ($PSCmdlet.ShouldProcess($it.Name, "Restore $($desired.Count) assignment target(s)")) {
            try {
                Save-IaAssignments -Item $it -Assignments $desired
                New-IaChangePlan -Item $it -Added @("restored $($desired.Count) target(s)") -Applied $true
            } catch {
                New-IaChangePlan -Item $it -Added @('restore') -ErrorText $_.Exception.Message
            }
        } else {
            New-IaChangePlan -Item $it -Added @("would restore $($desired.Count) target(s)")
        }
    }
}
