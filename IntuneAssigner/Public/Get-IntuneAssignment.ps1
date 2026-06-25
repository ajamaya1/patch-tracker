function Get-IntuneAssignment {
    <#
    .SYNOPSIS
        List Intune resources and their assignments, with groups resolved.
    .DESCRIPTION
        Enumerates every assignable area (or a subset via -Area/-Type) and
        returns one object per resource with a rich .Assignments collection and
        a flattened .AssignedTo summary. Use -Flat for one row per assignment
        edge (handy for Format-Table / Export-Csv).
    .EXAMPLE
        Get-IntuneAssignment -AssignedOnly | Format-Table Area, Name, AssignedTo
    .EXAMPLE
        Get-IntuneAssignment -Area Apps -Flat
    #>
    [CmdletBinding()]
    param(
        [string[]]$Area,
        [string[]]$Type,
        [switch]$AssignedOnly,
        [switch]$Flat
    )
    $progress = { param($m) Write-Verbose $m }
    $items = Get-IaInventory -Area $Area -Type $Type -AssignedOnly:$AssignedOnly -Progress $progress

    if ($Flat) {
        foreach ($it in $items) {
            if (-not $it.Assignments) {
                [pscustomobject]@{ Area = $it.Area; ResourceType = $it.ResourceType; Resource = $it.Name
                    Platform = $it.Platform; AssignedTo = '(unassigned)'; Intent = ''; Filter = ''; Exclude = $false }
                continue
            }
            foreach ($a in $it.Assignments) {
                [pscustomobject]@{
                    Area = $it.Area; ResourceType = $it.ResourceType; Resource = $it.Name; Platform = $it.Platform
                    AssignedTo = (Get-IaTargetDisplay -Target $a.Target)
                    Intent = $a.Intent; Filter = $a.Target.FilterName; Exclude = $a.Target.IsExclude
                }
            }
        }
        return
    }

    foreach ($it in $items) {
        $summary = if ($it.Assignments) { (($it.Assignments | ForEach-Object { Get-IaTargetDisplay -Target $_.Target }) -join '; ') } else { '(unassigned)' }
        $it | Add-Member -NotePropertyName AssignedTo -NotePropertyValue $summary -Force -PassThru
    }
}
