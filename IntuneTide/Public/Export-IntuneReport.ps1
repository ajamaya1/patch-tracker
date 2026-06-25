function Export-IntuneReport {
    <#
    .SYNOPSIS
        Run ANY Intune report via the official export API and return the rows.

    .DESCRIPTION
        Submits a report to deviceManagement/reports/exportJobs, polls it to
        completion, downloads the (zipped) CSV and parses it into objects. Any
        valid Intune report name works — see Get-IntuneReportCatalog for common
        ones. This is the "run any report possible" surface; the per-workload
        cmdlets (Get-IntuneAppInstallStatus, …) are faster shortcuts for the
        common questions.

    .PARAMETER Name
        The Intune report name, e.g. 'DeviceInstallStatusByApp',
        'DeviceNonCompliance', 'AllAppsList'. Case-sensitive as Graph expects.

    .PARAMETER Filter
        An OData-style report filter string, e.g.
        "(ApplicationId eq '<guid>')" for DeviceInstallStatusByApp.

    .PARAMETER Select
        Restrict the returned columns to these names.

    .PARAMETER Search
        Free-text search passed to the report.

    .PARAMETER As
        Output shape: Object (default, parsed rows), Csv, or Json.

    .PARAMETER Path
        When set with -As Csv/Json, write to this file instead of the pipeline.

    .PARAMETER TimeoutSec
        How long to wait for the async job (default 300s).

    .EXAMPLE
        Export-IntuneReport -Name DeviceNonCompliance | Format-Table

        Pull every noncompliant device.

    .EXAMPLE
        $app = Get-IntuneAssignment -Type mobileApps | Where-Object Name -eq 'Microsoft Edge'
        Export-IntuneReport -Name DeviceInstallStatusByApp -Filter "(ApplicationId eq '$($app.Id)')"

        Per-device install status for a specific app.

    .EXAMPLE
        Export-IntuneReport -Name AllAppsList -As Csv -Path apps.csv

        Save the full app list to CSV.

    .OUTPUTS
        PSCustomObject rows (As Object), or a CSV/JSON string / file.

    .LINK
        Get-IntuneReportCatalog
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [string]$Filter,
        [string[]]$Select,
        [string]$Search,
        [ValidateSet('Object', 'Csv', 'Json')][string]$As = 'Object',
        [string]$Path,
        [int]$TimeoutSec = 300
    )
    $known = (Get-IaReportCatalog).Name
    if ($Name -notin $known) {
        Write-Verbose "Report '$Name' is not in the built-in catalog; submitting anyway (Graph validates it)."
    }
    $rows = Invoke-IaReportExport -ReportName $Name -Filter $Filter -Select $Select -Search $Search `
        -TimeoutSec $TimeoutSec -OnStatus { param($s) Write-Verbose "report '$Name' status: $s" }

    switch ($As) {
        'Csv' {
            if ($Path) { $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding utf8; Write-Verbose "Wrote $Path" }
            else { $rows | ConvertTo-Csv -NoTypeInformation }
        }
        'Json' {
            $json = $rows | ConvertTo-Json -Depth 6
            if ($Path) { $json | Set-Content -Path $Path -Encoding utf8; Write-Verbose "Wrote $Path" } else { $json }
        }
        default { $rows }
    }
}
