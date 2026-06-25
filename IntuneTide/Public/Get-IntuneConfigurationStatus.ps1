function Get-IntuneConfigurationStatus {
    <#
    .SYNOPSIS
        Per-device deployment status for a device configuration profile
        (success / error / conflict / notApplicable / pending).

    .DESCRIPTION
        Reads deviceStatuses for a classic device configuration profile. Note:
        Settings Catalog policies (configurationPolicies) don't expose
        deviceStatuses — for those use
        Export-IntuneReport -Name ConfigurationPolicyAggregate.

    .PARAMETER Profile
        Configuration profile display name or id (deviceConfigurations).

    .PARAMETER Status
        Only return rows with this status.

    .PARAMETER Summary
        Also emit the status-overview counts.

    .EXAMPLE
        Get-IntuneConfigurationStatus -Profile "Win 11 Security Baseline" |
            Where-Object Status -in error,conflict

        Devices erroring or conflicting on a profile.

    .OUTPUTS
        PSCustomObject: Device, User, Status, Platform, LastReported.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Profile,
        [string]$Status,
        [switch]$Summary
    )
    $id = Resolve-IaResourceId -ListPath 'deviceManagement/deviceConfigurations' -Value $Profile
    if ($Summary) {
        $o = Invoke-IaRequest -Method GET -Uri (Resolve-IaUri "deviceManagement/deviceConfigurations/$id/deviceStatusOverview")
        Write-Information (ConvertTo-IaDeploymentCounts -Overview $o -Kind config) -InformationAction Continue
    }
    $rows = Get-IaCollection "deviceManagement/deviceConfigurations/$id/deviceStatuses"
    foreach ($r in $rows) {
        if ($Status -and $r.status -ne $Status) { continue }
        [pscustomobject]@{
            Device = $r.deviceDisplayName; User = $r.userPrincipalName; Status = $r.status
            Platform = $r.platform; LastReported = $r.lastReportedDateTime
        }
    }
}
