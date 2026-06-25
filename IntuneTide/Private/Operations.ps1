# Higher-level assignment operations shared by the public cmdlets and the TUI:
# copy/mirror, bulk-assign, templates and audit. Each returns plain objects so
# callers (cmdlet output, Spectre tables) can render them however they like.

function Copy-IaTargetForGroup {
    param([object]$Source, [string]$DstId, [string]$DstName, [bool]$IncludeFilters = $true)
    [pscustomobject]@{
        Kind         = $Source.Kind
        IsExclude    = $Source.IsExclude
        GroupId      = $DstId
        GroupName    = $DstName
        FilterId     = if ($IncludeFilters) { $Source.FilterId } else { $null }
        FilterType   = if ($IncludeFilters -and $Source.FilterId) { $Source.FilterType } else { 'none' }
        FilterName   = if ($IncludeFilters) { $Source.FilterName } else { $null }
        CollectionId = $Source.CollectionId
        ODataType    = $Source.ODataType
    }
}

function Get-IaCopyCandidates {
    param([object[]]$Items, [string]$SrcId)
    @($Items | Where-Object { Get-IaItemGroupEdges -Item $_ -GroupId $SrcId })
}

function Invoke-IaCopy {
    # Mirror src group's assignments onto dst; optionally restrict to IncludeIds.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Items,
        [Parameter(Mandatory)][string]$SrcId,
        [Parameter(Mandatory)][string]$DstId,
        [string]$DstName,
        [string[]]$IncludeIds,
        [bool]$IncludeFilters = $true,
        [switch]$Commit
    )
    if (-not $DstName) { $DstName = Resolve-IaGroupName -Id $DstId }
    foreach ($it in $Items) {
        if ($IncludeIds -and ($it.Id -notin $IncludeIds)) { continue }
        $edges = Get-IaItemGroupEdges -Item $it -GroupId $SrcId
        if (-not $edges) { continue }

        $merged = [System.Collections.Generic.List[object]]::new()
        $existing = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($a in $it.Assignments) { [void]$merged.Add($a); [void]$existing.Add((Get-IaTargetMatchKey -Target $a.Target)) }

        $added = @()
        foreach ($edge in $edges) {
            $newTarget = Copy-IaTargetForGroup -Source $edge.Target -DstId $DstId -DstName $DstName -IncludeFilters $IncludeFilters
            $key = Get-IaTargetMatchKey -Target $newTarget
            if ($existing.Contains($key)) { continue }
            [void]$existing.Add($key)
            [void]$merged.Add([pscustomobject]@{ Target = $newTarget; Intent = $edge.Intent; Settings = $edge.Settings; Raw = $edge.Raw })
            $added += (Get-IaTargetDisplay -Target $newTarget) + $(if ($edge.Intent) { " [$($edge.Intent)]" } else { '' })
        }
        if (-not $added) { continue }

        $applied = $false; $err = $null
        if ($Commit) {
            try { Save-IaAssignments -Item $it -Assignments $merged.ToArray(); $applied = $true }
            catch { $err = $_.Exception.Message }
        }
        New-IaChangePlan -Item $it -Added $added -Applied $applied -ErrorText $err
    }
}

function Invoke-IaBulkAssign {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Items,
        [Parameter(Mandatory)][string]$GroupId,
        [string]$GroupName,
        [switch]$Exclude,
        [string]$Intent,
        [string]$FilterId,
        [string]$FilterType = 'include',
        [switch]$Commit
    )
    if (-not $GroupName) { $GroupName = Resolve-IaGroupName -Id $GroupId }
    foreach ($it in $Items) {
        $rt = Find-IaResourceType -Key $it.ResourceType
        $target = New-IaGroupTarget -GroupId $GroupId -Exclude:$Exclude -FilterId $FilterId -FilterType $FilterType
        $target.GroupName = $GroupName
        $key = Get-IaTargetMatchKey -Target $target
        if (($it.Assignments | ForEach-Object { Get-IaTargetMatchKey -Target $_.Target }) -contains $key) {
            New-IaChangePlan -Item $it -Skipped 'already assigned'
            continue
        }
        $effIntent = if ($rt.HasIntent -and $Intent) { $Intent } else { $null }
        $newAssign = [pscustomobject]@{ Target = $target; Intent = $effIntent; Settings = $null; Raw = $null }
        $merged = @($it.Assignments) + $newAssign
        $applied = $false; $err = $null
        if ($Commit) {
            try { Save-IaAssignments -Item $it -Assignments $merged; $applied = $true }
            catch { $err = $_.Exception.Message }
        }
        $desc = (Get-IaTargetDisplay -Target $target) + $(if ($effIntent) { " [$effIntent]" } else { '' })
        New-IaChangePlan -Item $it -Added @($desc) -Applied $applied -ErrorText $err
    }
}

function New-IaTemplateFromGroup {
    param([Parameter(Mandatory)][object[]]$Items, [Parameter(Mandatory)][string]$GroupId, [string]$Name, [string]$Description = '')
    $resources = foreach ($it in $Items) {
        foreach ($e in (Get-IaItemGroupEdges -Item $it -GroupId $GroupId)) {
            [pscustomobject]@{
                resource_type = $it.ResourceType
                name          = $it.Name
                id            = $it.Id
                intent        = $e.Intent
                exclude       = $e.Target.IsExclude
                filter_name   = $e.Target.FilterName
                filter_type   = if ($e.Target.FilterId) { $e.Target.FilterType } else { 'include' }
            }
        }
    }
    [pscustomobject]@{ name = $Name; description = $Description; version = 1; resources = @($resources) }
}

function Invoke-IaTemplateApply {
    param([Parameter(Mandatory)][object]$Template, [Parameter(Mandatory)][object[]]$Items, [Parameter(Mandatory)][string]$GroupId, [string]$GroupName, [switch]$Commit)
    if (-not $GroupName) { $GroupName = Resolve-IaGroupName -Id $GroupId }
    $byId = @{}; $byName = @{}
    foreach ($it in $Items) { $byId[$it.Id] = $it; $byName["$($it.ResourceType)|$($it.Name)"] = $it }
    foreach ($tr in $Template.resources) {
        $it = if ($tr.id -and $byId.ContainsKey($tr.id)) { $byId[$tr.id] } elseif ($byName.ContainsKey("$($tr.resource_type)|$($tr.name)")) { $byName["$($tr.resource_type)|$($tr.name)"] } else { $null }
        if (-not $it) {
            New-IaChangePlan -Item ([pscustomobject]@{ Area = (Find-IaResourceType -Key $tr.resource_type).Area; ResourceType = $tr.resource_type; Name = $tr.name; Id = $tr.id }) -Skipped 'resource not found in tenant'
            continue
        }
        $rt = Find-IaResourceType -Key $it.ResourceType
        $filterId = if ($tr.filter_name) { Get-IaFilterIdByName -Name $tr.filter_name } else { $null }
        $target = New-IaGroupTarget -GroupId $GroupId -Exclude:([bool]$tr.exclude) -FilterId $filterId -FilterType ($tr.filter_type ?? 'include')
        $target.GroupName = $GroupName
        $key = Get-IaTargetMatchKey -Target $target
        if (($it.Assignments | ForEach-Object { Get-IaTargetMatchKey -Target $_.Target }) -contains $key) {
            New-IaChangePlan -Item $it -Skipped 'already assigned'; continue
        }
        $effIntent = if ($rt.HasIntent) { $tr.intent } else { $null }
        $merged = @($it.Assignments) + [pscustomobject]@{ Target = $target; Intent = $effIntent; Settings = $null; Raw = $null }
        $applied = $false; $err = $null
        if ($Commit) {
            try { Save-IaAssignments -Item $it -Assignments $merged; $applied = $true } catch { $err = $_.Exception.Message }
        }
        New-IaChangePlan -Item $it -Added @((Get-IaTargetDisplay -Target $target)) -Applied $applied -ErrorText $err
    }
}

function Get-IaEmptyTargetedGroups {
    param([Parameter(Mandatory)][object[]]$Items)
    $targeted = @{}
    foreach ($it in $Items) {
        foreach ($a in $it.Assignments) {
            $gid = $a.Target.GroupId
            if ($gid) {
                if (-not $targeted.ContainsKey($gid)) { $targeted[$gid] = @() }
                $targeted[$gid] += "$($it.Area)/$($it.Name)"
            }
        }
    }
    foreach ($gid in $targeted.Keys) {
        if ((Get-IaGroupMemberCount -Id $gid) -eq 0) {
            [pscustomobject]@{ GroupName = (Resolve-IaGroupName -Id $gid); GroupId = $gid; Resources = $targeted[$gid] }
        }
    }
}
