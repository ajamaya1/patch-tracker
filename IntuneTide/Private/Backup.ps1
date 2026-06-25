# Backup / restore / drift for assignments. A backup is a JSON snapshot of every
# resource's full assignment set; restore re-applies a snapshot (via the /assign
# action, which replaces the set); drift diffs current state against a snapshot.

function ConvertTo-IaAssignmentSnapshot {
    # Serialize one inventory item's assignments to a portable shape.
    param([Parameter(Mandatory)][object]$Item)
    [pscustomobject]@{
        resourceType = $Item.ResourceType
        id           = $Item.Id
        name         = $Item.Name
        area         = $Item.Area
        assignments  = @($Item.Assignments | ForEach-Object {
                [pscustomobject]@{
                    kind         = $_.Target.Kind
                    groupId      = $_.Target.GroupId
                    groupName    = $_.Target.GroupName
                    isExclude    = [bool]$_.Target.IsExclude
                    filterId     = $_.Target.FilterId
                    filterType   = $_.Target.FilterType
                    odataType    = $_.Target.ODataType
                    collectionId = $_.Target.CollectionId
                    intent       = $_.Intent
                    settings     = $_.Settings
                    raw          = $_.Raw
                }
            })
    }
}

function ConvertFrom-IaAssignmentSnapshot {
    # Rebuild Assignment objects (with a Target) from a snapshot resource, so the
    # write engine (Save-IaAssignments / ConvertTo-IaAssignmentBody) can re-post.
    param([Parameter(Mandatory)][object]$SnapResource)
    foreach ($a in $SnapResource.assignments) {
        $t = [pscustomobject]@{
            Kind         = $a.kind
            IsExclude    = [bool]$a.isExclude
            GroupId      = $a.groupId
            GroupName    = $a.groupName
            FilterId     = $a.filterId
            FilterType   = if ($a.filterType) { $a.filterType } else { 'none' }
            FilterName   = $null
            CollectionId = $a.collectionId
            ODataType    = $a.odataType
        }
        [pscustomobject]@{ Target = $t; Intent = $a.intent; Settings = $a.settings; Raw = $a.raw }
    }
}

function Get-IaSnapshotTargetKeys {
    # Match keys for a snapshot resource's targets (for drift/diff).
    param([Parameter(Mandatory)][object]$SnapResource)
    @(ConvertFrom-IaAssignmentSnapshot -SnapResource $SnapResource | ForEach-Object {
            Get-IaTargetMatchKey -Target $_.Target
        })
}

function Read-IaSnapshot {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "Snapshot file not found: $Path" }
    Get-Content -Path $Path -Raw | ConvertFrom-Json
}
