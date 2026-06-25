# Reporting engine. Two layers:
#  1. The Intune *report export API* (deviceManagement/reports/exportJobs) — this
#     runs ANY Intune report by name with filters/columns, async: submit -> poll
#     -> download the zipped CSV -> parse. This is what makes reporting
#     "extremely robust": the full Intune report catalog is reachable.
#  2. Fast per-resource status endpoints (deviceStatuses / overviews) for the
#     common app/config/compliance questions without the async round-trip.
#
# Every Graph call still flows through Invoke-IaRequest; the one extra seam is
# Invoke-IaDownload (the SAS blob fetch), kept separate so tests can mock it.

function ConvertTo-IaDateTime {
    # Accept a DateTime, an absolute string, or a relative '7d'/'24h'/'30m'/'2w'.
    param([Parameter(Mandatory)][string]$Value)
    if ($Value -match '^\s*(\d+)\s*([smhdw])\s*$') {
        $n = [int]$Matches[1]
        $span = switch ($Matches[2]) {
            's' { [timespan]::FromSeconds($n) }
            'm' { [timespan]::FromMinutes($n) }
            'h' { [timespan]::FromHours($n) }
            'd' { [timespan]::FromDays($n) }
            'w' { [timespan]::FromDays($n * 7) }
        }
        return (Get-Date).ToUniversalTime().Subtract($span)
    }
    [datetime]::Parse($Value).ToUniversalTime()
}

function Invoke-IaDownload {
    # Download a pre-authenticated SAS blob URL to a file (no bearer needed).
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$OutFile)
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -ErrorAction Stop
}

function ConvertFrom-IaReportZip {
    # Read the CSV out of a downloaded report .zip and parse to objects.
    param([Parameter(Mandatory)][string]$ZipPath)
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $entry = $zip.Entries | Where-Object { $_.Name -like '*.csv' } | Select-Object -First 1
        if (-not $entry) { return @() }
        $reader = New-Object System.IO.StreamReader($entry.Open())
        try { $csv = $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $zip.Dispose() }
    if ([string]::IsNullOrWhiteSpace($csv)) { return @() }
    , @($csv | ConvertFrom-Csv)
}

function Invoke-IaReportExport {
    # Run any Intune export report by name. Returns parsed rows (objects).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ReportName,
        [string]$Filter,
        [string[]]$Select,
        [string]$Search,
        [hashtable]$ExtraBody,
        [int]$TimeoutSec = 300,
        [int]$PollSeconds = 3,
        [scriptblock]$OnStatus
    )
    $body = @{ reportName = $ReportName; format = 'csv' }
    if ($Filter) { $body.filter = $Filter }
    if ($Select) { $body.select = @($Select) }
    if ($Search) { $body.search = $Search }
    if ($ExtraBody) { foreach ($k in $ExtraBody.Keys) { $body[$k] = $ExtraBody[$k] } }

    $job = Invoke-IaRequest -Method POST -Uri (Resolve-IaUri 'deviceManagement/reports/exportJobs') -Body $body
    $id = $job.id
    if (-not $id) { throw "Report '$ReportName' was not accepted by Graph (no job id returned)." }

    $start = Get-Date
    while ($job.status -in 'notStarted', 'inProgress', $null) {
        if ($OnStatus) { & $OnStatus $job.status }
        if (((Get-Date) - $start).TotalSeconds -gt $TimeoutSec) {
            throw "Report '$ReportName' timed out after ${TimeoutSec}s (last status: $($job.status))."
        }
        Start-Sleep -Seconds $PollSeconds
        $job = Invoke-IaRequest -Method GET -Uri (Resolve-IaUri "deviceManagement/reports/exportJobs('$id')")
    }
    if ($job.status -ne 'completed') {
        throw "Report '$ReportName' failed (status: $($job.status))."
    }
    if (-not $job.url) { return @() }

    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        Invoke-IaDownload -Url $job.url -OutFile $tmp
        return ConvertFrom-IaReportZip -ZipPath $tmp
    } finally {
        Remove-Item -Path $tmp -ErrorAction SilentlyContinue
    }
}

# ---- per-resource status helpers -------------------------------------
function ConvertTo-IaDeploymentCounts {
    # Normalize an installSummary (apps) or deviceStatusOverview (config /
    # compliance) into a consistent counts object.
    param([Parameter(Mandatory)][object]$Overview, [ValidateSet('app', 'config')][string]$Kind = 'config')
    if ($Kind -eq 'app') {
        [pscustomobject][ordered]@{
            Success       = [int]$Overview.installedDeviceCount
            Failed        = [int]$Overview.failedDeviceCount
            NotApplicable = [int]$Overview.notApplicableDeviceCount
            Pending       = [int]$Overview.pendingInstallDeviceCount
            NotInstalled  = [int]$Overview.notInstalledDeviceCount
        }
    } else {
        [pscustomobject][ordered]@{
            Success       = [int]$Overview.successCount
            Error         = [int]$Overview.errorCount
            Failed        = [int]$Overview.failedCount
            Conflict      = [int]$Overview.conflictCount
            NotApplicable = [int]$Overview.notApplicableCount
            Pending       = [int]$Overview.pendingCount
        }
    }
}

function Get-IaResourceDeploymentCounts {
    # Fetch + normalize deployment counts for one inventory item, or $null if
    # the resource type has no simple overview (use Export-IntuneReport instead).
    param([Parameter(Mandatory)][object]$Item)
    switch ($Item.ResourceType) {
        'mobileApps' {
            $o = Invoke-IaRequest -Method GET -Uri (Resolve-IaUri "deviceAppManagement/mobileApps/$($Item.Id)/installSummary")
            return ConvertTo-IaDeploymentCounts -Overview $o -Kind app
        }
        { $_ -in 'deviceConfigurations', 'windowsUpdateRings' } {
            $o = Invoke-IaRequest -Method GET -Uri (Resolve-IaUri "deviceManagement/deviceConfigurations/$($Item.Id)/deviceStatusOverview")
            return ConvertTo-IaDeploymentCounts -Overview $o -Kind config
        }
        'deviceCompliancePolicies' {
            $o = Invoke-IaRequest -Method GET -Uri (Resolve-IaUri "deviceManagement/deviceCompliancePolicies/$($Item.Id)/deviceStatusOverview")
            return ConvertTo-IaDeploymentCounts -Overview $o -Kind config
        }
        default { return $null }
    }
}

function Resolve-IaResourceId {
    # Resolve a resource (app/profile/policy) name-or-id within a list path.
    param([Parameter(Mandatory)][string]$ListPath, [Parameter(Mandatory)][string]$Value, [string]$NameField = 'displayName')
    if (Test-IaGuid $Value) { return $Value }
    $esc = $Value.Replace("'", "''")
    $hit = Get-IaCollection "$ListPath`?`$filter=$NameField eq '$esc'&`$select=id,$NameField" | Select-Object -First 1
    if (-not $hit) {
        # Some endpoints don't allow $filter on name; fall back to client-side match.
        $hit = Get-IaCollection "$ListPath`?`$select=id,$NameField" | Where-Object { $_.$NameField -eq $Value } | Select-Object -First 1
    }
    if (-not $hit) { throw "No resource named '$Value' under $ListPath." }
    $hit.id
}

function Get-IaReportCatalog {
    # A curated catalog of common Intune export report names. ANY valid report
    # name works with Export-IntuneReport; this is for discovery/auto-complete.
    @(
        [pscustomobject]@{ Name = 'Devices'; Area = 'Devices'; Description = 'All managed devices inventory' }
        [pscustomobject]@{ Name = 'DevicesWithInventory'; Area = 'Devices'; Description = 'Devices with extended hardware inventory' }
        [pscustomobject]@{ Name = 'DeviceCompliance'; Area = 'Compliance'; Description = 'Device compliance state' }
        [pscustomobject]@{ Name = 'DeviceNonCompliance'; Area = 'Compliance'; Description = 'Noncompliant devices only' }
        [pscustomobject]@{ Name = 'ComplianceSettingNonComplianceReport'; Area = 'Compliance'; Description = 'Per-setting noncompliance' }
        [pscustomobject]@{ Name = 'DeviceInstallStatusByApp'; Area = 'Apps'; Description = 'Per-device install status for an app (needs filter ApplicationId)' }
        [pscustomobject]@{ Name = 'UserInstallStatusAggregateByApp'; Area = 'Apps'; Description = 'Per-user install status for an app' }
        [pscustomobject]@{ Name = 'AppInstallStatusAggregate'; Area = 'Apps'; Description = 'Install status aggregate across apps' }
        [pscustomobject]@{ Name = 'AllAppsList'; Area = 'Apps'; Description = 'All apps in the tenant' }
        [pscustomobject]@{ Name = 'AppInvByDevice'; Area = 'Apps'; Description = 'Discovered app inventory by device' }
        [pscustomobject]@{ Name = 'AppInvAggregate'; Area = 'Apps'; Description = 'Discovered app inventory aggregate' }
        [pscustomobject]@{ Name = 'ConfigurationPolicyAggregate'; Area = 'Configuration'; Description = 'Settings-catalog policy status aggregate' }
        [pscustomobject]@{ Name = 'DeviceConfigurationDeviceActivity'; Area = 'Configuration'; Description = 'Config profile device activity' }
        [pscustomobject]@{ Name = 'DeviceConfigurationUserActivity'; Area = 'Configuration'; Description = 'Config profile user activity' }
        [pscustomobject]@{ Name = 'FeatureUpdatePolicyFailuresAggregate'; Area = 'Windows Update'; Description = 'Feature update failures' }
        [pscustomobject]@{ Name = 'FeatureUpdateDeviceState'; Area = 'Windows Update'; Description = 'Feature update per-device state' }
        [pscustomobject]@{ Name = 'QualityUpdateDeviceStatusByPolicy'; Area = 'Windows Update'; Description = 'Quality update per-device status' }
        [pscustomobject]@{ Name = 'DriverUpdatePolicyStatusSummary'; Area = 'Windows Update'; Description = 'Driver update policy status' }
        [pscustomobject]@{ Name = 'Malware'; Area = 'Security'; Description = 'Detected malware' }
        [pscustomobject]@{ Name = 'ActiveMalware'; Area = 'Security'; Description = 'Active malware detections' }
        [pscustomobject]@{ Name = 'DefenderAgents'; Area = 'Security'; Description = 'Defender agent health' }
        [pscustomobject]@{ Name = 'UnhealthyDefenderAgents'; Area = 'Security'; Description = 'Unhealthy Defender agents' }
        [pscustomobject]@{ Name = 'FirewallStatus'; Area = 'Security'; Description = 'Firewall status per device' }
        [pscustomobject]@{ Name = 'GroupPolicyMigrationReport'; Area = 'Configuration'; Description = 'GPO migration readiness' }
    )
}
