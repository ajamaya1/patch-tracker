function Get-IntuneApprovalRequest {
    <#
    .SYNOPSIS
        Report on Intune Multi Admin Approval (MAA) requests and their outcomes.

    .DESCRIPTION
        Reads deviceManagement/operationApprovalRequests — the access-policy
        "multiple admin approval" requests that gate sensitive changes (app
        deployments, scripts, role/scope-tag edits, device actions). Returns one
        normalized row per request: who requested, the change type, status,
        approver, justification and expiry. Useful for auditing privileged
        change-approval activity. Requires the
        DeviceManagementRBAC.Read.All / DeviceManagementConfiguration.Read.All
        scopes depending on tenant config.

    .PARAMETER Status
        Filter by request status (e.g. needsApproval, approved, rejected,
        completed, expired, cancelled).

    .PARAMETER Type
        Filter by the operation approval policy type (e.g. app, script,
        deviceConfiguration, roleScopeTags, deviceAction).

    .PARAMETER Requestor
        Filter to requests whose requestor display name / UPN contains this text.

    .EXAMPLE
        Get-IntuneApprovalRequest -Status needsApproval | Format-Table

        Everything currently waiting on an approver.

    .EXAMPLE
        Get-IntuneApprovalRequest -Status rejected -Type app

        Rejected app-deployment approval requests.

    .OUTPUTS
        PSCustomObject: Requested, Requestor, Type, Status, Approver,
        Justification, Expires, Completed.

    .NOTES
        Multi Admin Approval must be enabled in the tenant (Tenant admin →
        Access policies). With it off, this returns nothing.
    #>
    [CmdletBinding()]
    param(
        [string]$Status,
        [string]$Type,
        [string]$Requestor
    )
    $q = 'deviceManagement/operationApprovalRequests?$orderby=requestDateTime desc'
    $rows = Get-IaCollection $q
    foreach ($r in $rows) {
        $reqName = $r.requestor.userPrincipalName
        if (-not $reqName) { $reqName = $r.requestor.user.displayName }
        if (-not $reqName) { $reqName = $r.requestor.displayName }
        $appName = $r.approver.userPrincipalName
        if (-not $appName) { $appName = $r.approver.user.displayName }
        if (-not $appName) { $appName = $r.approver.displayName }
        $row = [pscustomobject]@{
            Requested     = ($r.requestDateTime ?? $r.createdDateTime)
            Requestor     = $reqName
            Type          = $r.operationApprovalPolicyType
            Status        = $r.status
            Approver      = $appName
            Justification = $r.requestJustification
            Expires       = $r.expirationDateTime
            Completed     = $r.completedDateTime
        }
        if ($Status -and $row.Status -ne $Status) { continue }
        if ($Type -and $row.Type -ne $Type) { continue }
        if ($Requestor -and "$($row.Requestor)" -notmatch [regex]::Escape($Requestor)) { continue }
        $row
    }
}
