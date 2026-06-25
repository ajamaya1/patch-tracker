function Get-IntuneActiveRole {
    <#
    .SYNOPSIS
        Show your currently-active directory roles (incl. PIM activations).

    .DESCRIPTION
        Lists the signed-in user's active role assignments with how they were
        assigned (Activated via PIM vs permanently Assigned) and when an
        activation expires. Handy to confirm you're elevated before a change.

    .EXAMPLE
        Get-IntuneActiveRole | Format-Table

    .OUTPUTS
        PSCustomObject: Role, AssignmentType, MemberType, StartDateTime, EndDateTime.
    #>
    [CmdletBinding()]
    param()
    foreach ($a in (Get-IaActiveRoles)) {
        [pscustomobject]@{
            Role           = $a.roleDefinition.displayName
            AssignmentType = $a.assignmentType
            MemberType     = $a.memberType
            StartDateTime  = $a.startDateTime
            EndDateTime    = $a.endDateTime
        }
    }
}
