function Enable-IntuneAdminRole {
    <#
    .SYNOPSIS
        Activate (elevate into) an eligible PIM role for this session.

    .DESCRIPTION
        Self-activates one of your PIM-eligible Entra directory roles via
        roleManagement/directory/roleAssignmentScheduleRequests (action
        selfActivate), so you're elevated before making Intune changes. The
        activation lasts for the requested duration, then auto-expires. If the
        role's PIM policy requires MFA, approval, or a ticket, Graph enforces
        it and the returned Status reflects that (e.g. PendingApproval).

        Delegated sign-in only (you activate your own eligibility).

    .PARAMETER Role
        The eligible role to activate (display name or roleDefinitionId).
        Defaults to 'Intune Administrator'. See Get-IntuneEligibleRole.

    .PARAMETER Justification
        Why you're elevating (required by most PIM policies).

    .PARAMETER Duration
        How long to stay active: ISO8601 (PT2H) or shorthand (2h / 30m / 1d).
        Default PT2H. The role's PIM policy caps the maximum.

    .PARAMETER TicketNumber
        Change/ticket reference, when the policy requires ticketing.

    .PARAMETER TicketSystem
        The ticketing system name that goes with -TicketNumber.

    .EXAMPLE
        Enable-IntuneAdminRole -Justification "Mirror Pilot->Prod app assignments"

        Activate Intune Administrator for 2 hours.

    .EXAMPLE
        Enable-IntuneAdminRole -Role "Intune Administrator" -Duration 8h `
            -Justification "Quarterly assignment cleanup" -TicketNumber CHG0102030 -TicketSystem ServiceNow

        Activate for 8 hours with a ticket reference.

    .OUTPUTS
        PSCustomObject: Role, Status, RequestId, Duration, Justification, Created.

    .LINK
        Get-IntuneEligibleRole
    .LINK
        Get-IntuneActiveRole
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$Role = 'Intune Administrator',
        [Parameter(Mandatory)][string]$Justification,
        [string]$Duration = 'PT2H',
        [string]$TicketNumber,
        [string]$TicketSystem
    )
    $me = Get-IaMyPrincipalId
    $match = Get-IaEligibleRoles -PrincipalId $me.Id |
        Where-Object { $_.roleDefinition.displayName -eq $Role -or $_.roleDefinitionId -eq $Role } |
        Select-Object -First 1
    if (-not $match) {
        throw "You have no PIM-eligible role matching '$Role'. Run Get-IntuneEligibleRole to see your options."
    }
    $iso = ConvertTo-IaIsoDuration $Duration
    $scope = if ($match.directoryScopeId) { $match.directoryScopeId } else { '/' }

    if ($PSCmdlet.ShouldProcess("$($match.roleDefinition.displayName) (as $($me.Upn))", "Activate PIM role for $iso")) {
        $req = Invoke-IaActivateRole -PrincipalId $me.Id -RoleDefinitionId $match.roleDefinitionId `
            -Duration $iso -Justification $Justification -DirectoryScopeId $scope `
            -TicketNumber $TicketNumber -TicketSystem $TicketSystem
        [pscustomobject]@{
            Role          = $match.roleDefinition.displayName
            Status        = $req.status
            RequestId     = $req.id
            Duration      = $iso
            Justification = $Justification
            Created       = $req.createdDateTime
        }
    }
}
