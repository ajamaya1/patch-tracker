# Normalized assignment model. Graph represents targets inconsistently across
# resource types; these helpers flatten that into one shape and render it back.

$script:IaTargetOData = @{
    '#microsoft.graph.groupAssignmentTarget'                       = @{ Kind = 'group';      Exclude = $false }
    '#microsoft.graph.exclusionGroupAssignmentTarget'             = @{ Kind = 'exclusion';  Exclude = $true }
    '#microsoft.graph.allLicensedUsersAssignmentTarget'          = @{ Kind = 'allUsers';   Exclude = $false }
    '#microsoft.graph.allDevicesAssignmentTarget'                = @{ Kind = 'allDevices'; Exclude = $false }
    '#microsoft.graph.configurationManagerCollectionAssignmentTarget' = @{ Kind = 'collection'; Exclude = $false }
    '#microsoft.graph.cloudPcManagementGroupAssignmentTarget'    = @{ Kind = 'group';      Exclude = $false }
}

function ConvertFrom-IaTarget {
    param([Parameter(Mandatory)][object]$Target)
    $odata = $Target.'@odata.type'
    $kindInfo = if ($odata -and $script:IaTargetOData.ContainsKey($odata)) { $script:IaTargetOData[$odata] } else { @{ Kind = 'unknown'; Exclude = $false } }
    [pscustomobject]@{
        Kind        = $kindInfo.Kind
        IsExclude   = $kindInfo.Exclude
        GroupId     = $Target.groupId
        GroupName   = $null
        FilterId    = $Target.deviceAndAppManagementAssignmentFilterId
        FilterType  = if ($Target.deviceAndAppManagementAssignmentFilterType) { $Target.deviceAndAppManagementAssignmentFilterType } else { 'none' }
        FilterName  = $null
        CollectionId = $Target.collectionId
        ODataType   = $odata
    }
}

function Get-IaTargetDisplay {
    param([Parameter(Mandatory)][object]$Target)
    $who = switch ($Target.Kind) {
        'allUsers'   { 'All Users' }
        'allDevices' { 'All Devices' }
        'collection' { "Collection $($Target.CollectionId)" }
        default      { if ($Target.GroupName) { $Target.GroupName } elseif ($Target.GroupId) { $Target.GroupId } else { '(unknown group)' } }
    }
    if ($Target.IsExclude) { $who = "EXCLUDE $who" }
    if ($Target.FilterId -and $Target.FilterType -ne 'none') {
        $fn = if ($Target.FilterName) { $Target.FilterName } else { $Target.FilterId }
        $who = "$who [filter $($Target.FilterType): $fn]"
    }
    $who
}

function Get-IaTargetMatchKey {
    param([Parameter(Mandatory)][object]$Target)
    '{0}|{1}|{2}|{3}|{4}' -f $Target.Kind, $Target.GroupId, $Target.CollectionId, $Target.FilterId, $Target.FilterType
}

function ConvertTo-IaTargetBody {
    # Render a target object back to a Graph 'target' hashtable, preserving the
    # original @odata.type when one was read (so Cloud PC group targets etc.
    # round-trip correctly).
    param([Parameter(Mandatory)][object]$Target)
    $odata = $Target.ODataType
    if (-not $odata) {
        $odata = switch ($Target.Kind) {
            'group'      { '#microsoft.graph.groupAssignmentTarget' }
            'exclusion'  { '#microsoft.graph.exclusionGroupAssignmentTarget' }
            'allUsers'   { '#microsoft.graph.allLicensedUsersAssignmentTarget' }
            'allDevices' { '#microsoft.graph.allDevicesAssignmentTarget' }
            'collection' { '#microsoft.graph.configurationManagerCollectionAssignmentTarget' }
            default      { '#microsoft.graph.groupAssignmentTarget' }
        }
    }
    $body = @{ '@odata.type' = $odata }
    if ($Target.Kind -in 'group', 'exclusion' -and $Target.GroupId) { $body.groupId = $Target.GroupId }
    if ($Target.Kind -eq 'collection' -and $Target.CollectionId) { $body.collectionId = $Target.CollectionId }
    if ($Target.FilterId -and $Target.FilterType -ne 'none') {
        $body.deviceAndAppManagementAssignmentFilterId = $Target.FilterId
        $body.deviceAndAppManagementAssignmentFilterType = $Target.FilterType
    }
    $body
}

function ConvertFrom-IaAssignment {
    param([Parameter(Mandatory)][object]$Item)
    [pscustomobject]@{
        Target   = ConvertFrom-IaTarget -Target $Item.target
        Intent   = $Item.intent
        Settings = $Item.settings
        Raw      = $Item
    }
}

function ConvertTo-IaAssignmentBody {
    # Render an assignment back to a Graph hashtable, preserving type-specific
    # fields (e.g. a remediation's runSchedule) read from Graph.
    param(
        [Parameter(Mandatory)][object]$Assignment,
        [string]$AssignmentODataType
    )
    $body = @{}
    if ($Assignment.Raw) {
        foreach ($p in $Assignment.Raw.PSObject.Properties) {
            if ($p.Name -in 'id', 'source', 'sourceId', 'target') { continue }
            $body[$p.Name] = $p.Value
        }
    }
    $body.target = ConvertTo-IaTargetBody -Target $Assignment.Target
    if ($null -ne $Assignment.Intent)   { $body.intent = $Assignment.Intent }
    if ($null -ne $Assignment.Settings) { $body.settings = $Assignment.Settings }
    if ($AssignmentODataType -and -not $body.ContainsKey('@odata.type')) {
        $body['@odata.type'] = $AssignmentODataType
    }
    $body
}

function New-IaGroupTarget {
    # Build a fresh target object for a group (used by bulk/template writes).
    param(
        [Parameter(Mandatory)][string]$GroupId,
        [switch]$Exclude,
        [string]$FilterId,
        [string]$FilterType = 'none'
    )
    [pscustomobject]@{
        Kind        = if ($Exclude) { 'exclusion' } else { 'group' }
        IsExclude   = [bool]$Exclude
        GroupId     = $GroupId
        GroupName   = $null
        FilterId    = $FilterId
        FilterType  = if ($FilterId) { $FilterType } else { 'none' }
        FilterName  = $null
        CollectionId = $null
        ODataType   = $null
    }
}
