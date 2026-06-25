# The inventory enumerator shared by every public cmdlet: read each resource
# type across all areas, attach and resolve assignments (group names, filter
# names, include/exclude, app intent, per-assignment settings).

function Get-IaPlatform {
    param([object]$Raw)
    foreach ($f in 'platforms', 'platform', 'platformType') {
        if ($Raw.$f -is [string] -and $Raw.$f) { return $Raw.$f }
    }
    $odata = $Raw.'@odata.type'
    if ($odata) {
        foreach ($tag in 'windows', 'ios', 'macOS', 'android') {
            if ($odata.ToLower().Contains($tag.ToLower())) { return $tag }
        }
    }
    $null
}

function Get-IaInventory {
    [CmdletBinding()]
    param(
        [string[]]$Area,
        [string[]]$Type,
        [switch]$AssignedOnly,
        [scriptblock]$Progress
    )
    $types = Resolve-IaResourceType -Area $Area -Type $Type
    $items = [System.Collections.Generic.List[object]]::new()

    foreach ($rt in $types) {
        if ($Progress) { & $Progress "Reading $($rt.Label) ($($rt.Area))…" }
        try {
            $path = "$($rt.ListPath)?`$select=id,$($rt.NameField)"
            if ($rt.ExpandAssignments) { $path += '&$expand=assignments' }
            $raws = Get-IaCollection -Path $path
        } catch {
            # A 403/404 on one area (no licence / no RBAC) must not abort the sweep.
            if ($Progress) { & $Progress "  skipped $($rt.Key): $($_.Exception.Message)" }
            continue
        }
        foreach ($raw in $raws) {
            if ($rt.ODataTypeContains) {
                $odata = "$($raw.'@odata.type')".ToLower()
                if (-not $odata.Contains($rt.ODataTypeContains.ToLower())) { continue }
            }
            $assigns = $null
            if ($rt.ExpandAssignments) { $assigns = $raw.assignments }
            else { $assigns = Get-IaCollection -Path "$($rt.ListPath)/$($raw.id)/assignments" }

            $name = $raw.$($rt.NameField)
            if (-not $name) { $name = $raw.displayName }
            if (-not $name) { $name = '(unnamed)' }

            $assignObjs = @()
            if ($assigns) { $assignObjs = @($assigns | ForEach-Object { ConvertFrom-IaAssignment -Item $_ }) }

            [void]$items.Add([pscustomobject]@{
                ResourceType = $rt.Key
                Area         = $rt.Area
                Id           = $raw.id
                Name         = $name
                Platform     = Get-IaPlatform -Raw $raw
                ODataType    = $raw.'@odata.type'
                Assignments  = $assignObjs
                Raw          = $raw
            })
        }
    }

    # ---- resolve group + filter names across the whole result set ----
    $gids = $items | ForEach-Object { $_.Assignments } | ForEach-Object { $_.Target.GroupId } | Where-Object { $_ }
    Resolve-IaGroupNames -Ids $gids
    Initialize-IaFilters
    foreach ($it in $items) {
        foreach ($a in $it.Assignments) {
            if ($a.Target.GroupId)  { $a.Target.GroupName  = Resolve-IaGroupName -Id $a.Target.GroupId }
            if ($a.Target.FilterId) { $a.Target.FilterName = Get-IaFilterName   -Id $a.Target.FilterId }
        }
    }

    $result = if ($AssignedOnly) { $items | Where-Object { $_.Assignments.Count -gt 0 } } else { $items }
    , @($result)
}

function Get-IaItemGroupEdges {
    # Assignments of an item that target a given group id.
    param([Parameter(Mandatory)][object]$Item, [Parameter(Mandatory)][string]$GroupId)
    @($Item.Assignments | Where-Object { $_.Target.GroupId -eq $GroupId })
}

function Get-IaItemGroupMode {
    # How a group targets an item: include | exclude | mixed | none.
    param([Parameter(Mandatory)][object]$Item, [Parameter(Mandatory)][string]$GroupId)
    $edges = Get-IaItemGroupEdges -Item $Item -GroupId $GroupId
    if (-not $edges) { return 'none' }
    $hasExcl = [bool]($edges | Where-Object { $_.Target.IsExclude })
    $hasIncl = [bool]($edges | Where-Object { -not $_.Target.IsExclude })
    if ($hasExcl -and $hasIncl) { return 'mixed' }
    if ($hasExcl) { return 'exclude' } else { return 'include' }
}
