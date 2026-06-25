function Copy-IntuneAssignment {
    <#
    .SYNOPSIS
        Mirror assignments from one group onto another (all or a chosen subset).
    .DESCRIPTION
        For each resource the source group is assigned to, adds an equivalent
        target for the destination group — preserving include/exclude, app
        install intent + settings, remediation schedules and (optionally)
        assignment filters. Narrow what gets mirrored with -Area/-Type/-NameLike
        or an explicit -Include list. Supports -WhatIf to preview.
    .EXAMPLE
        Copy-IntuneAssignment -FromGroup Pilot -ToGroup Prod -Area Configuration -WhatIf
    .EXAMPLE
        Copy-IntuneAssignment -FromGroup Pilot -ToGroup Prod -NameLike Defender
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$FromGroup,
        [Parameter(Mandatory)][string]$ToGroup,
        [string[]]$Area,
        [string[]]$Type,
        [string]$NameLike,
        [string[]]$Include,
        [switch]$NoFilters
    )
    $src = Resolve-IaGroup -Value $FromGroup
    $dst = Resolve-IaGroup -Value $ToGroup
    $items = Get-IaInventory -Area $Area -Type $Type -AssignedOnly
    if ($NameLike) { $items = @($items | Where-Object { $_.Name -like "*$NameLike*" }) }
    $includeIds = $null
    if ($Include) { $includeIds = @($items | Where-Object { $_.Id -in $Include -or $_.Name -in $Include } | ForEach-Object Id) }

    $commit = $PSCmdlet.ShouldProcess($dst.DisplayName, "Mirror assignments from '$($src.DisplayName)'")
    Invoke-IaCopy -Items $items -SrcId $src.Id -DstId $dst.Id -DstName $dst.DisplayName `
        -IncludeIds $includeIds -IncludeFilters (-not $NoFilters) -Commit:$commit
}
