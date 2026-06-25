function Get-IntuneDeploymentSummary {
    <#
    .SYNOPSIS
        Roll-up of deployment success/failure across resources — optionally
        scoped to everything assigned to a group. Ties reporting to assignments.

    .DESCRIPTION
        For each assigned resource that exposes a status overview (apps, device
        configuration profiles, update rings, compliance policies), fetches the
        success/error/failed/conflict/notApplicable/pending counts and emits one
        row per resource plus the per-row failure rate. With -Group, only
        resources that the group is assigned to are included — answering
        "for everything assigned to <group>, what actually deployed?".

    .PARAMETER Group
        Limit to resources assigned to this group (display name or id).

    .PARAMETER Area
        Limit to one or more areas (Apps, Compliance, Configuration, …).

    .PARAMETER Type
        Limit to one or more resource type keys.

    .PARAMETER FailuresOnly
        Only emit resources that have at least one failed/error device.

    .EXAMPLE
        Get-IntuneDeploymentSummary -Group "All Workstations" | Format-Table

        Deployment health for everything assigned to a group.

    .EXAMPLE
        Get-IntuneDeploymentSummary -Area Apps -FailuresOnly | Sort-Object FailRate -Descending

        Apps with the worst install failure rates.

    .OUTPUTS
        PSCustomObject: Area, ResourceType, Resource, Success, Failed, Error,
        Conflict, NotApplicable, Pending, Total, FailRate.
    #>
    [CmdletBinding()]
    param(
        [string]$Group,
        [string[]]$Area,
        [string[]]$Type,
        [switch]$FailuresOnly
    )
    $items = Get-IaInventory -Area $Area -Type $Type -AssignedOnly
    if ($Group) {
        $g = Resolve-IaGroup -Value $Group
        $items = @($items | Where-Object { Get-IaItemGroupEdges -Item $_ -GroupId $g.Id })
    }
    foreach ($it in $items) {
        $c = $null
        try { $c = Get-IaResourceDeploymentCounts -Item $it } catch { continue }
        if (-not $c) { continue }
        $failed = ([int]$c.Failed) + ([int]$c.Error)
        $total = 0; foreach ($p in $c.PSObject.Properties) { $total += [int]$p.Value }
        $row = [ordered]@{
            Area = $it.Area; ResourceType = $it.ResourceType; Resource = $it.Name
            Success = [int]$c.Success; Failed = [int]$c.Failed
        }
        if ($null -ne $c.Error) { $row.Error = [int]$c.Error }
        if ($null -ne $c.Conflict) { $row.Conflict = [int]$c.Conflict }
        $row.NotApplicable = [int]$c.NotApplicable
        if ($null -ne $c.Pending) { $row.Pending = [int]$c.Pending }
        $row.Total = $total
        $row.FailRate = if ($total) { [math]::Round($failed / $total * 100, 1) } else { 0 }
        if ($FailuresOnly -and $failed -eq 0) { continue }
        [pscustomobject]$row
    }
}
