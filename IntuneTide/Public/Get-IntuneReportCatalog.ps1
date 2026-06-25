function Get-IntuneReportCatalog {
    <#
    .SYNOPSIS
        List well-known Intune report names usable with Export-IntuneReport.

    .DESCRIPTION
        Returns a curated catalog of common Intune export-report names with the
        area and a short description. ANY valid Intune report name works with
        Export-IntuneReport — this catalog is for discovery and tab-friendly
        browsing, not an exhaustive or enforced list.

    .PARAMETER Area
        Filter the catalog to one or more areas (e.g. Apps, Compliance,
        Security, Configuration, Devices, 'Windows Update').

    .EXAMPLE
        Get-IntuneReportCatalog | Format-Table

        Show every known report name with its area and description.

    .EXAMPLE
        Get-IntuneReportCatalog -Area Apps

        Just the app-related reports (install status, inventory, etc.).

    .OUTPUTS
        PSCustomObject with Name, Area, Description.

    .LINK
        Export-IntuneReport
    #>
    [CmdletBinding()]
    param([string[]]$Area)

    $catalog = Get-IaReportCatalog
    if ($Area) {
        $set = @($Area | ForEach-Object { $_.ToLower() })
        $catalog = $catalog | Where-Object { $set -contains $_.Area.ToLower() }
    }
    $catalog | Sort-Object Area, Name
}
