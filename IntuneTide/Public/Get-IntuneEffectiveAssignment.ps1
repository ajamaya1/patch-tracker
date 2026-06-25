function Get-IntuneEffectiveAssignment {
    <#
    .SYNOPSIS
        What actually lands on a user or device (what-if), via group membership.
    .DESCRIPTION
        Resolves the subject's transitive group membership and evaluates every
        assignment against it. Exclusions win over includes (as Intune does);
        includes bound to an assignment filter are flagged, since the filter
        may further narrow whether the policy truly applies.
    .EXAMPLE
        Get-IntuneEffectiveAssignment -User jdoe@contoso.com | Where-Object Effective
    .EXAMPLE
        Get-IntuneEffectiveAssignment -Device LAPTOP-01
    #>
    [CmdletBinding(DefaultParameterSetName = 'User')]
    param(
        [Parameter(ParameterSetName = 'User', Mandatory)][string]$User,
        [Parameter(ParameterSetName = 'Device', Mandatory)][string]$Device,
        [string[]]$Area,
        [string[]]$Type
    )
    $kind = $PSCmdlet.ParameterSetName.ToLower()
    $value = if ($kind -eq 'user') { $User } else { $Device }
    $subject = Get-IaSubjectGroups -Kind $kind -Value $value
    $gids = $subject.GroupIds
    $allUsers = $kind -eq 'user'
    $allDevices = $kind -eq 'device'

    $items = Get-IaInventory -Area $Area -Type $Type -AssignedOnly
    foreach ($it in $items) {
        $includes = @(); $excludes = @(); $filtered = $false
        foreach ($a in $it.Assignments) {
            $t = $a.Target
            $applies = ($t.Kind -eq 'allUsers' -and $allUsers) -or
                       ($t.Kind -eq 'allDevices' -and $allDevices) -or
                       ($t.GroupId -and $gids -contains $t.GroupId)
            if (-not $applies) { continue }
            if ($t.IsExclude) { $excludes += $a }
            else { $includes += $a; if ($t.FilterId) { $filtered = $true } }
        }
        if (-not $includes) { continue }
        [pscustomobject]@{
            Area      = $it.Area
            Resource  = $it.Name
            Effective = (-not $excludes)
            Excluded  = [bool]$excludes
            Via       = (($includes | ForEach-Object {
                            switch ($_.Target.Kind) {
                                'allUsers'   { 'All Users' }
                                'allDevices' { 'All Devices' }
                                default      { $_.Target.GroupName }
                            } }) -join ', ')
            Filtered  = $filtered
        }
    }
}
