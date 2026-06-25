function Add-IntuneBulkAssignment {
    <#
    .SYNOPSIS
        Assign one group to many resources at once.
    .EXAMPLE
        Add-IntuneBulkAssignment -Group "All Macs" -Area Compliance -WhatIf
    .EXAMPLE
        Add-IntuneBulkAssignment -Group Kiosks -Type mobileApps -NameLike Edge -Intent required -Filter "Corp Windows"
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Group,
        [string[]]$Area,
        [string[]]$Type,
        [string]$NameLike,
        [switch]$Exclude,
        [string]$Intent,
        [string]$Filter,
        [ValidateSet('include', 'exclude')][string]$FilterType = 'include'
    )
    $g = Resolve-IaGroup -Value $Group
    $items = Get-IaInventory -Area $Area -Type $Type
    if ($NameLike) { $items = @($items | Where-Object { $_.Name -like "*$NameLike*" }) }
    $filterId = if ($Filter) { Get-IaFilterIdByName -Name $Filter } else { $null }

    $commit = $PSCmdlet.ShouldProcess("$($items.Count) resource(s)", "Assign group '$($g.DisplayName)'")
    Invoke-IaBulkAssign -Items $items -GroupId $g.Id -GroupName $g.DisplayName `
        -Exclude:$Exclude -Intent $Intent -FilterId $filterId -FilterType $FilterType -Commit:$commit
}
