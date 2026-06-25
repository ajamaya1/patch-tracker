function Compare-IntuneAssignment {
    <#
    .SYNOPSIS
        Diff the assignments of two groups.
    .DESCRIPTION
        Emits one row per resource that either group touches, classified as
        OnlyA, OnlyB, Both, or Conflict (one includes while the other excludes).
    .EXAMPLE
        Compare-IntuneAssignment -GroupA "Pilot Ring" -GroupB "Production Ring" |
            Where-Object Relationship -eq OnlyA
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GroupA,
        [Parameter(Mandatory)][string]$GroupB,
        [string[]]$Area,
        [string[]]$Type
    )
    $a = Resolve-IaGroup -Value $GroupA
    $b = Resolve-IaGroup -Value $GroupB
    $items = Get-IaInventory -Area $Area -Type $Type -AssignedOnly
    foreach ($it in $items) {
        $am = Get-IaItemGroupMode -Item $it -GroupId $a.Id
        $bm = Get-IaItemGroupMode -Item $it -GroupId $b.Id
        if ($am -eq 'none' -and $bm -eq 'none') { continue }
        $rel =
            if ($am -ne 'none' -and $bm -eq 'none') { 'OnlyA' }
            elseif ($bm -ne 'none' -and $am -eq 'none') { 'OnlyB' }
            elseif (($am -eq 'include' -and $bm -eq 'exclude') -or ($am -eq 'exclude' -and $bm -eq 'include')) { 'Conflict' }
            else { 'Both' }
        [pscustomobject]@{
            Area = $it.Area; Resource = $it.Name; Relationship = $rel; AMode = $am; BMode = $bm
        }
    }
}
