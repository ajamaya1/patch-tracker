# Privileged Identity Management (PIM) — self-activate an eligible Entra role
# from within the session so writes happen elevated. Uses the Graph PIM
# directory role-management endpoints (v1.0). Delegated sign-in only (you
# activate *your own* eligibility; app-only has no user to elevate).

function ConvertTo-IaIsoDuration {
    # Accept an ISO8601 duration (PT2H) or shorthand (2h / 30m / 8h / 1d).
    param([Parameter(Mandatory)][string]$Value)
    if ($Value -match '^P') { return $Value }
    if ($Value -match '^\s*(\d+)\s*([mhd])\s*$') {
        $n = [int]$Matches[1]
        switch ($Matches[2]) {
            'm' { return "PT${n}M" }
            'h' { return "PT${n}H" }
            'd' { return "P${n}D" }
        }
    }
    throw "Invalid duration '$Value'. Use e.g. PT2H, 2h, 30m, 1d."
}

function Get-IaMyPrincipalId {
    $me = Invoke-IaRequest -Method GET -Uri (Resolve-IaUri -V1 'me?$select=id,userPrincipalName')
    if (-not $me.id) {
        throw "PIM activation needs a delegated sign-in (interactive / device-code); the current context has no signed-in user."
    }
    [pscustomobject]@{ Id = $me.id; Upn = $me.userPrincipalName }
}

function Get-IaEligibleRoles {
    param([string]$PrincipalId)
    if (-not $PrincipalId) { $PrincipalId = (Get-IaMyPrincipalId).Id }
    Get-IaCollection -V1 ("roleManagement/directory/roleEligibilityScheduleInstances" +
        "?`$filter=principalId eq '$PrincipalId'&`$expand=roleDefinition")
}

function Get-IaActiveRoles {
    param([string]$PrincipalId)
    if (-not $PrincipalId) { $PrincipalId = (Get-IaMyPrincipalId).Id }
    Get-IaCollection -V1 ("roleManagement/directory/roleAssignmentScheduleInstances" +
        "?`$filter=principalId eq '$PrincipalId'&`$expand=roleDefinition")
}

function Invoke-IaActivateRole {
    param(
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)][string]$RoleDefinitionId,
        [Parameter(Mandatory)][string]$Duration,
        [Parameter(Mandatory)][string]$Justification,
        [string]$DirectoryScopeId = '/',
        [string]$TicketNumber,
        [string]$TicketSystem
    )
    $body = @{
        action           = 'selfActivate'
        principalId      = $PrincipalId
        roleDefinitionId = $RoleDefinitionId
        directoryScopeId = $DirectoryScopeId
        justification    = $Justification
        scheduleInfo     = @{
            startDateTime = (Get-Date).ToUniversalTime().ToString('o')
            expiration    = @{ type = 'afterDuration'; duration = $Duration }
        }
    }
    if ($TicketNumber) { $body.ticketInfo = @{ ticketNumber = $TicketNumber; ticketSystem = $TicketSystem } }
    Invoke-IaRequest -Method POST -Uri (Resolve-IaUri -V1 'roleManagement/directory/roleAssignmentScheduleRequests') -Body $body
}

function Test-IaPrivileged {
    # Is an Intune-relevant admin role currently active for the signed-in user?
    param([string[]]$RoleNames = @('Intune Administrator', 'Global Administrator', 'Privileged Role Administrator'))
    try {
        $active = Get-IaActiveRoles
    } catch { return $true }  # app-only / can't check — don't block
    [bool]($active | Where-Object { $_.roleDefinition.displayName -in $RoleNames })
}
