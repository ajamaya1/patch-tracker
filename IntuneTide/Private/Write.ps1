# Write engine. The /assign action replaces the whole assignment set, so every
# write reads the current assignments, merges, and posts the complete list.

function Find-IaResourceType {
    param([Parameter(Mandatory)][string]$Key)
    Get-IaResourceRegistry | Where-Object { $_.Key -eq $Key } | Select-Object -First 1
}

function ConvertTo-IaAssignBody {
    param([Parameter(Mandatory)][object]$ResourceType, [object[]]$Assignments)
    $entries = @()
    foreach ($a in $Assignments) {
        $entries += , (ConvertTo-IaAssignmentBody -Assignment $a -AssignmentODataType $ResourceType.AssignmentODataType)
    }
    @{ $ResourceType.AssignBodyKey = $entries }
}

function Save-IaAssignments {
    # Commit a merged assignment set onto one resource via its /assign action.
    param([Parameter(Mandatory)][object]$Item, [Parameter(Mandatory)][object[]]$Assignments)
    $rt = Find-IaResourceType -Key $Item.ResourceType
    $body = ConvertTo-IaAssignBody -ResourceType $rt -Assignments $Assignments
    Invoke-IaAssign -ListPath $rt.ListPath -Id $Item.Id -Body $body
}

function New-IaChangePlan {
    param([object]$Item, [string[]]$Added = @(), [string]$Skipped, [bool]$Applied = $false, [string]$ErrorText)
    [pscustomobject]@{
        Area         = $Item.Area
        ResourceType = $Item.ResourceType
        ResourceName = $Item.Name
        ResourceId   = $Item.Id
        Added        = $Added
        Skipped      = $Skipped
        Applied      = $Applied
        Error        = $ErrorText
    }
}
