function Export-IntuneHtmlReport {
    <#
    .SYNOPSIS
        Build a rich, interactive HTML assignment report with PSWriteHTML.

    .DESCRIPTION
        Renders a polished, self-contained HTML report using PSWriteHTML:
        searchable/sortable/filterable DataTables, tabs, KPI tiles, a
        per-area chart, and conditional row coloring (exclusions in red,
        unassigned dimmed). Far nicer than the built-in static report, and
        great for sharing with stakeholders. Optionally fold in deployment
        and drift sections.

    .PARAMETER Path
        Output .html path.

    .PARAMETER Area
        Limit to one or more areas.

    .PARAMETER Type
        Limit to one or more resource type keys.

    .PARAMETER DriftAgainst
        Also add a "Drift" tab comparing the current state to this snapshot.

    .PARAMETER Show
        Open the report in the browser when done.

    .EXAMPLE
        Export-IntuneHtmlReport -Path tide.html -Show

        Interactive report of every assignment, opened in the browser.

    .EXAMPLE
        Export-IntuneHtmlReport -Path apps.html -Area Apps -DriftAgainst baseline.json

        App assignments plus a drift tab against a baseline.

    .NOTES
        Requires PSWriteHTML: Install-Module PSWriteHTML -Scope CurrentUser
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Area,
        [string[]]$Type,
        [string]$DriftAgainst,
        [switch]$Show
    )
    if (-not (Get-Command New-HTML -ErrorAction SilentlyContinue)) {
        throw "Export-IntuneHtmlReport needs the PSWriteHTML module. Install it with: Install-Module PSWriteHTML -Scope CurrentUser"
    }

    $items = Get-IaInventory -Area $Area -Type $Type
    $rows = @(ConvertTo-IaFlatRows -Items $items)
    $assigned = @($items | Where-Object { $_.Assignments.Count -gt 0 }).Count
    $byArea = $items | Group-Object Area | ForEach-Object {
        [pscustomobject]@{ Area = $_.Name; Total = $_.Count
            Assigned = @($_.Group | Where-Object { $_.Assignments.Count -gt 0 }).Count }
    }
    $drift = if ($DriftAgainst) { @(Get-IntuneAssignmentDrift -Path $DriftAgainst -Area $Area -Type $Type) } else { @() }

    New-HTML -TitleText 'TIDE — Intune Assignments' -FilePath $Path -ShowHTML:$Show {
        New-HTMLHeader {
            New-HTMLText -Text 'TIDE — Targeted Intune Deployment & Endpoints' -FontSize 26 -FontWeight bold -Color '#1f9d8f'
        }
        New-HTMLSection -HeaderText 'Overview' -Invisible {
            New-HTMLPanel { New-HTMLText -Text "Resources: $($items.Count)" -FontSize 18 }
            New-HTMLPanel { New-HTMLText -Text "Assigned: $assigned" -FontSize 18 -Color '#1f9d55' }
            New-HTMLPanel { New-HTMLText -Text "Unassigned: $($items.Count - $assigned)" -FontSize 18 -Color '#8a9ac0' }
        }
        New-HTMLTabStyle -BorderRadius 8px
        New-HTMLTab -Name 'Assignments' -IconSolid table {
            New-HTMLTable -DataTable $rows -Filtering -SearchHighlight -PagingLength 25 {
                New-HTMLTableCondition -Name 'exclude' -ComparisonType string -Operator eq -Value 'True' -BackgroundColor Salmon -Color White
                New-HTMLTableCondition -Name 'target' -ComparisonType string -Operator like -Value '*unassigned*' -Color Gray
                New-HTMLTableCondition -Name 'intent' -ComparisonType string -Operator eq -Value 'required' -BackgroundColor LightGreen
            }
        }
        New-HTMLTab -Name 'By area' -IconSolid 'chart-bar' {
            New-HTMLChart -Title 'Assigned vs total by area' {
                foreach ($a in $byArea) {
                    New-ChartBar -Name $a.Area -Value $a.Assigned
                }
            }
            New-HTMLTable -DataTable $byArea -HideFooter
        }
        if ($drift.Count) {
            New-HTMLTab -Name "Drift ($($drift.Count))" -IconSolid 'code-branch' {
                New-HTMLTable -DataTable $drift -Filtering {
                    New-HTMLTableCondition -Name 'Change' -ComparisonType string -Operator eq -Value 'Removed' -BackgroundColor Salmon -Color White
                    New-HTMLTableCondition -Name 'Change' -ComparisonType string -Operator eq -Value 'Gone' -BackgroundColor Salmon -Color White
                    New-HTMLTableCondition -Name 'Change' -ComparisonType string -Operator eq -Value 'Added' -BackgroundColor LightGreen
                    New-HTMLTableCondition -Name 'Change' -ComparisonType string -Operator eq -Value 'New' -BackgroundColor LightBlue
                }
            }
        }
    }
    Write-Verbose "Wrote interactive report to $Path"
}
