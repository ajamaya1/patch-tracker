function Get-IntuneAssignmentAudit {
    <#
    .SYNOPSIS
        Tenant-wide assignment audit summary (counts, top groups, gaps).
    .DESCRIPTION
        Returns a structured object: totals, per-area assigned/total, most-used
        groups, filters in use, unassigned resources, and (with -CheckEmptyGroups)
        targeted groups that have zero members.
    .EXAMPLE
        (Get-IntuneAssignmentAudit -CheckEmptyGroups).EmptyGroups
    #>
    [CmdletBinding()]
    param([string[]]$Area, [string[]]$Type, [switch]$CheckEmptyGroups)

    $items = Get-IaInventory -Area $Area -Type $Type
    $assigned = @($items | Where-Object { $_.Assignments.Count -gt 0 })
    $edges = @($items | ForEach-Object { $_.Assignments })

    $groupUsage = @{}; $filterUsage = @{}; $virtual = @{}; $excl = 0
    foreach ($it in $items) {
        foreach ($a in $it.Assignments) {
            $t = $a.Target
            if ($t.IsExclude) { $excl++ }
            if ($t.Kind -in 'allUsers', 'allDevices') {
                $d = Get-IaTargetDisplay -Target $t; $virtual[$d] = 1 + ($virtual[$d] ?? 0)
            } elseif ($t.GroupId) {
                $n = $t.GroupName ?? $t.GroupId; $groupUsage[$n] = 1 + ($groupUsage[$n] ?? 0)
            }
            if ($t.FilterId) { $fn = $t.FilterName ?? $t.FilterId; $filterUsage[$fn] = 1 + ($filterUsage[$fn] ?? 0) }
        }
    }

    $byArea = $items | Group-Object Area | ForEach-Object {
        [pscustomobject]@{ Area = $_.Name; Total = $_.Count
            Assigned = @($_.Group | Where-Object { $_.Assignments.Count -gt 0 }).Count }
    }

    [pscustomobject]@{
        ResourceCount   = $items.Count
        AssignedCount   = $assigned.Count
        UnassignedCount = $items.Count - $assigned.Count
        EdgeCount       = $edges.Count
        ExclusionCount  = $excl
        ByArea          = $byArea
        VirtualTargets  = $virtual.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Target = $_.Key; Count = $_.Value } }
        TopGroups       = $groupUsage.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 20 |
                          ForEach-Object { [pscustomobject]@{ Group = $_.Key; Count = $_.Value } }
        Filters         = $filterUsage.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Filter = $_.Key; Count = $_.Value } }
        Unassigned      = $items | Where-Object { $_.Assignments.Count -eq 0 } | ForEach-Object { [pscustomobject]@{ Area = $_.Area; Resource = $_.Name } }
        EmptyGroups     = if ($CheckEmptyGroups) { @(Get-IaEmptyTargetedGroups -Items $items) } else { $null }
    }
}
