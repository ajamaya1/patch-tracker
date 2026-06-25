function Get-IntuneAuditLog {
    <#
    .SYNOPSIS
        Query the Intune audit log — who changed what, when.

    .DESCRIPTION
        Reads deviceManagement/auditEvents and returns one normalized row per
        change: timestamp, actor (admin/app), activity, operation type, result,
        category and the affected resource. Great for change reviews and
        compliance evidence. Requires DeviceManagementApps.Read.All /
        DeviceManagementConfiguration.Read.All (audit is surfaced under those).

    .PARAMETER Since
        Only events on/after this time. Accepts a DateTime or a relative string
        like '7d', '24h', '30m'.

    .PARAMETER Actor
        Filter to an actor whose UPN/app name contains this text.

    .PARAMETER Category
        Filter to an audit category (e.g. Application, DeviceConfiguration,
        Compliance, Enrollment, Role).

    .PARAMETER Activity
        Filter to activities whose display name contains this text
        (e.g. 'Assign', 'Delete', 'Patch').

    .PARAMETER Result
        Filter by result (Success / Failure).

    .PARAMETER Top
        Cap the number of (most recent) events returned.

    .EXAMPLE
        Get-IntuneAuditLog -Since 7d -Activity Assign | Format-Table

        Every assignment change in the last 7 days.

    .EXAMPLE
        Get-IntuneAuditLog -Since 24h -Actor jdoe@contoso.com -Result Failure

        Failed admin actions by a user in the last day.

    .OUTPUTS
        PSCustomObject: When, Actor, ActorType, Activity, Operation, Result,
        Category, Resource.
    #>
    [CmdletBinding()]
    param(
        [string]$Since,
        [string]$Actor,
        [string]$Category,
        [string]$Activity,
        [ValidateSet('Success', 'Failure')][string]$Result,
        [int]$Top
    )
    $filters = @()
    if ($Since) {
        $dt = ConvertTo-IaDateTime $Since
        $filters += "activityDateTime ge $($dt.ToString('o'))"
    }
    if ($Category) { $filters += "category eq '$Category'" }
    $q = 'deviceManagement/auditEvents?$orderby=activityDateTime desc'
    if ($filters) { $q += '&$filter=' + ($filters -join ' and ') }

    $events = Get-IaCollection $q
    $n = 0
    foreach ($e in $events) {
        $actor = $e.actor.userPrincipalName
        if (-not $actor) { $actor = $e.actor.applicationDisplayName }
        $resource = ($e.resources | Select-Object -First 1).displayName
        $row = [pscustomobject]@{
            When = $e.activityDateTime; Actor = $actor; ActorType = $e.actor.type
            Activity = $e.displayName; Operation = $e.activityOperationType
            Result = $e.activityResult; Category = $e.category; Resource = $resource
        }
        if ($Actor -and "$($row.Actor)" -notmatch [regex]::Escape($Actor)) { continue }
        if ($Activity -and "$($row.Activity)" -notmatch [regex]::Escape($Activity)) { continue }
        if ($Result -and $row.Result -ne $Result) { continue }
        $row
        if ($Top -and (++$n) -ge $Top) { break }
    }
}
