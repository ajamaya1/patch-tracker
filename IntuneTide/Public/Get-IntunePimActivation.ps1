function Get-IntunePimActivation {
    <#
    .SYNOPSIS
        Report on recent PIM role-activation requests (elevations).

    .DESCRIPTION
        Reads roleManagement/directory/roleAssignmentScheduleRequests to report
        on privileged role activations — who elevated into what, when, the
        justification and the outcome. By default shows your own requests;
        -All reports tenant-wide (needs RoleManagement.Read.Directory /
        appropriate PIM read permissions).

    .PARAMETER All
        Report every user's activation requests, not just your own.

    .PARAMETER Status
        Filter by request status (e.g. Provisioned, PendingApproval, Denied,
        Revoked, Canceled).

    .EXAMPLE
        Get-IntunePimActivation | Format-Table

        Your recent elevations.

    .EXAMPLE
        Get-IntunePimActivation -All -Status PendingApproval

        Tenant-wide activations awaiting approval.

    .OUTPUTS
        PSCustomObject: Created, Principal, Role, Action, Status, Justification, RequestId.
    #>
    [CmdletBinding()]
    param([switch]$All, [string]$Status)

    $q = 'roleManagement/directory/roleAssignmentScheduleRequests?$expand=roleDefinition,principal&$orderby=createdDateTime desc'
    if (-not $All) {
        $me = Get-IaMyPrincipalId
        $q = "roleManagement/directory/roleAssignmentScheduleRequests?`$filter=principalId eq '$($me.Id)'&`$expand=roleDefinition,principal&`$orderby=createdDateTime desc"
    }
    foreach ($r in (Get-IaCollection -V1 $q)) {
        $principal = $r.principal.userPrincipalName
        if (-not $principal) { $principal = $r.principal.displayName }
        $row = [pscustomobject]@{
            Created       = $r.createdDateTime
            Principal     = $principal
            Role          = $r.roleDefinition.displayName
            Action        = $r.action
            Status        = $r.status
            Justification = $r.justification
            RequestId     = $r.id
        }
        if ($Status -and $row.Status -ne $Status) { continue }
        $row
    }
}
