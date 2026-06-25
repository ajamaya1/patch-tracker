function Get-IntuneComplianceStatus {
    <#
    .SYNOPSIS
        Compliance status by policy, by device, or a tenant summary.

    .DESCRIPTION
        Three modes:
          -Policy <name|id>  → per-device status for one compliance policy.
          -Device <name|id>  → every compliance policy state for one device.
          (neither)          → the tenant compliance state summary.
        States: compliant / noncompliant / error / conflict / notApplicable /
        inGracePeriod / configManager.

    .PARAMETER Policy
        Compliance policy display name or id.

    .PARAMETER Device
        Managed device name or id.

    .PARAMETER Status
        Only return rows with this state.

    .EXAMPLE
        Get-IntuneComplianceStatus -Policy "Windows 11 Corp Compliance" -Status noncompliant

        Noncompliant devices for a policy.

    .EXAMPLE
        Get-IntuneComplianceStatus -Device "LAPTOP-01"

        Every compliance policy state for one device.

    .EXAMPLE
        Get-IntuneComplianceStatus

        Tenant-wide compliant/noncompliant/error counts.

    .OUTPUTS
        PSCustomObject (shape depends on mode).
    #>
    [CmdletBinding(DefaultParameterSetName = 'Summary')]
    param(
        [Parameter(ParameterSetName = 'Policy', Mandatory, Position = 0)][string]$Policy,
        [Parameter(ParameterSetName = 'Device', Mandatory)][string]$Device,
        [string]$Status
    )
    switch ($PSCmdlet.ParameterSetName) {
        'Policy' {
            $id = Resolve-IaResourceId -ListPath 'deviceManagement/deviceCompliancePolicies' -Value $Policy
            $rows = Get-IaCollection "deviceManagement/deviceCompliancePolicies/$id/deviceStatuses"
            foreach ($r in $rows) {
                if ($Status -and $r.status -ne $Status) { continue }
                [pscustomobject]@{ Device = $r.deviceDisplayName; User = $r.userPrincipalName
                    Status = $r.status; Platform = $r.platform; LastReported = $r.lastReportedDateTime }
            }
        }
        'Device' {
            $did = Resolve-IaResourceId -ListPath 'deviceManagement/managedDevices' -Value $Device -NameField 'deviceName'
            $rows = Get-IaCollection "deviceManagement/managedDevices/$did/deviceCompliancePolicyStates"
            foreach ($r in $rows) {
                if ($Status -and $r.state -ne $Status) { continue }
                [pscustomobject]@{ Policy = $r.displayName; State = $r.state; Platform = $r.platformType
                    Version = $r.version }
            }
        }
        default {
            $s = Invoke-IaRequest -Method GET -Uri (Resolve-IaUri 'deviceManagement/deviceCompliancePolicyDeviceStateSummary')
            [pscustomobject][ordered]@{
                Compliant = [int]$s.compliantDeviceCount; Noncompliant = [int]$s.nonCompliantDeviceCount
                Error = [int]$s.errorDeviceCount; Conflict = [int]$s.conflictDeviceCount
                NotApplicable = [int]$s.notApplicableDeviceCount; InGracePeriod = [int]$s.inGracePeriodCount
                RemediatedDevices = [int]$s.remediatedDeviceCount; Unknown = [int]$s.unknownDeviceCount
            }
        }
    }
}
