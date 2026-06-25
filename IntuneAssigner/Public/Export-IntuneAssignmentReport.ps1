function Export-IntuneAssignmentReport {
    <#
    .SYNOPSIS
        Export all assignments to an HTML, CSV or JSON report.
    .EXAMPLE
        Export-IntuneAssignmentReport -Format Html -Path assignments.html
    .EXAMPLE
        Export-IntuneAssignmentReport -Format Csv -Path assignments.csv -Area Apps
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Html', 'Csv', 'Json')][string]$Format,
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Area,
        [string[]]$Type,
        [string]$Title = 'Intune Assignments'
    )
    $items = Get-IaInventory -Area $Area -Type $Type
    switch ($Format) {
        'Html' {
            New-IaHtmlReport -Items $items -Title $Title | Set-Content -Path $Path -Encoding utf8
        }
        'Csv' {
            ConvertTo-IaFlatRows -Items $items | Export-Csv -Path $Path -NoTypeInformation -Encoding utf8
        }
        'Json' {
            $payload = foreach ($it in $items) {
                [pscustomobject]@{
                    area = $it.Area; resource_type = $it.ResourceType; id = $it.Id; name = $it.Name; platform = $it.Platform
                    assignments = @($it.Assignments | ForEach-Object {
                        [pscustomobject]@{ kind = $_.Target.Kind; group_id = $_.Target.GroupId; group_name = $_.Target.GroupName
                            exclude = $_.Target.IsExclude; intent = $_.Intent; filter_name = $_.Target.FilterName
                            filter_type = $(if ($_.Target.FilterId) { $_.Target.FilterType } else { $null }) }
                    })
                }
            }
            $payload | ConvertTo-Json -Depth 8 | Set-Content -Path $Path -Encoding utf8
        }
    }
    Write-Verbose "Wrote $Format report to $Path"
}
