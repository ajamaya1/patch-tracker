function Get-IntuneAppInstallStatus {
    <#
    .SYNOPSIS
        Per-device or per-user install status for an app (succeeded / failed /
        not applicable / pending / not installed).

    .DESCRIPTION
        Reads the app's deviceStatuses or userStatuses from Graph and returns a
        normalized row per device/user, with the install state and error detail.
        Add -Summary for the roll-up counts. For tenant-scale extracts use
        Export-IntuneReport -Name DeviceInstallStatusByApp.

    .PARAMETER App
        App display name or id (mobileApps).

    .PARAMETER By
        Pivot by Device (default) or User.

    .PARAMETER Status
        Only return rows with this install state (e.g. failed, installed,
        notApplicable, pending, notInstalled).

    .PARAMETER Summary
        Also emit the install-summary counts object (to the verbose/info view).

    .EXAMPLE
        Get-IntuneAppInstallStatus -App "Microsoft Edge" | Where-Object Status -eq failed

        Every device where Edge failed to install.

    .EXAMPLE
        Get-IntuneAppInstallStatus -App "Company Portal" -By User | Format-Table

        Per-user install rollup for Company Portal.

    .OUTPUTS
        PSCustomObject: Device/User, Status, Detail, User, ErrorCode, LastModified.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$App,
        [ValidateSet('Device', 'User')][string]$By = 'Device',
        [string]$Status,
        [switch]$Summary
    )
    $id = Resolve-IaResourceId -ListPath 'deviceAppManagement/mobileApps' -Value $App
    if ($Summary) {
        $o = Invoke-IaRequest -Method GET -Uri (Resolve-IaUri "deviceAppManagement/mobileApps/$id/installSummary")
        Write-Information (ConvertTo-IaDeploymentCounts -Overview $o -Kind app) -InformationAction Continue
    }
    $nav = if ($By -eq 'User') { 'userStatuses' } else { 'deviceStatuses' }
    $rows = Get-IaCollection "deviceAppManagement/mobileApps/$id/$nav"
    foreach ($r in $rows) {
        $out = if ($By -eq 'User') {
            [pscustomobject]@{
                User = $r.userPrincipalName; Status = $r.installState
                Installed = $r.installedDeviceCount; Failed = $r.failedDeviceCount
                NotInstalled = $r.notInstalledDeviceCount; LastModified = $r.lastModifiedDateTime
            }
        } else {
            [pscustomobject]@{
                Device = $r.deviceName; Status = $r.installState; Detail = $r.installStateDetail
                User = $r.userPrincipalName; ErrorCode = $r.errorCode; LastModified = $r.lastModifiedDateTime
            }
        }
        if ($Status -and $out.Status -ne $Status) { continue }
        $out
    }
}
