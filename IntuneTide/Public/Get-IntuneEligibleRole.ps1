function Get-IntuneEligibleRole {
    <#
    .SYNOPSIS
        List the PIM-eligible Entra roles you can activate.

    .DESCRIPTION
        Shows the directory roles the signed-in user is *eligible* for via
        Privileged Identity Management (not yet active). Use the Role name with
        Enable-IntuneAdminRole to activate one. Delegated sign-in only.

    .EXAMPLE
        Get-IntuneEligibleRole | Format-Table

        See every role you could elevate into.

    .OUTPUTS
        PSCustomObject: Role, RoleDefinitionId, Scope, MemberType, EndDateTime.

    .LINK
        Enable-IntuneAdminRole
    #>
    [CmdletBinding()]
    param()
    foreach ($e in (Get-IaEligibleRoles)) {
        [pscustomobject]@{
            Role             = $e.roleDefinition.displayName
            RoleDefinitionId = $e.roleDefinitionId
            Scope            = $e.directoryScopeId
            MemberType       = $e.memberType
            EndDateTime      = $e.endDateTime
        }
    }
}
