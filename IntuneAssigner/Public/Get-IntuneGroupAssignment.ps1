function Get-IntuneGroupAssignment {
    <#
    .SYNOPSIS
        Reverse lookup: everything a group is assigned to.
    .EXAMPLE
        Get-IntuneGroupAssignment -Group "All Workstations" | Format-Table
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Group,
        [string[]]$Area,
        [string[]]$Type
    )
    $g = Resolve-IaGroup -Value $Group
    $items = Get-IaInventory -Area $Area -Type $Type -AssignedOnly
    foreach ($it in $items) {
        foreach ($e in (Get-IaItemGroupEdges -Item $it -GroupId $g.Id)) {
            [pscustomobject]@{
                Area     = $it.Area
                Resource = $it.Name
                Mode     = if ($e.Target.IsExclude) { 'EXCLUDE' } else { 'include' }
                Intent   = $e.Intent
                Filter   = if ($e.Target.FilterId) { "$($e.Target.FilterType):$($e.Target.FilterName)" } else { '' }
                Group    = $g.DisplayName
            }
        }
    }
}
