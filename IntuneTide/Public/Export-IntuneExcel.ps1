function Export-IntuneExcel {
    <#
    .SYNOPSIS
        Export any TIDE output to a beautifully-formatted Excel workbook.

    .DESCRIPTION
        Pipes any objects (assignments, install/compliance status, deployment
        summary, drift, audit log, …) to a styled .xlsx via the ImportExcel
        module: a banded table, frozen + bold header, auto-filter, auto-sized
        columns, and smart conditional formatting that colors common status
        columns (Status / Change / Relationship / Exclude / Effective:
        green = good, red = bad, amber = pending). Call repeatedly with
        -Append + -WorksheetName to build a multi-tab workbook.

    .PARAMETER InputObject
        The objects to export (accepts pipeline).

    .PARAMETER Path
        Output .xlsx path.

    .PARAMETER WorksheetName
        Worksheet/tab name (default 'Sheet1').

    .PARAMETER Title
        Optional bold title row above the table.

    .PARAMETER Append
        Add a worksheet to an existing workbook instead of overwriting.

    .PARAMETER Show
        Open the workbook when done.

    .EXAMPLE
        Get-IntuneAssignment -Flat | Export-IntuneExcel -Path tide.xlsx -WorksheetName Assignments -Title 'All assignments'

        A formatted assignments sheet with exclude/unassigned coloring.

    .EXAMPLE
        Get-IntuneDeploymentSummary -FailuresOnly | Export-IntuneExcel -Path tide.xlsx -WorksheetName Failures -Append
        Get-IntuneAssignmentDrift -Path base.json | Export-IntuneExcel -Path tide.xlsx -WorksheetName Drift -Append -Show

        Build a multi-tab workbook (assignments + failures + drift) and open it.

    .NOTES
        Requires the ImportExcel module:
        Install-Module ImportExcel -Scope CurrentUser
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][object[]]$InputObject,
        [Parameter(Mandatory)][string]$Path,
        [string]$WorksheetName = 'Sheet1',
        [string]$Title,
        [switch]$Append,
        [switch]$Show
    )
    begin {
        if (-not (Get-Command Export-Excel -ErrorAction SilentlyContinue)) {
            throw "Export-IntuneExcel needs the ImportExcel module. Install it with: Install-Module ImportExcel -Scope CurrentUser"
        }
        $rows = [System.Collections.Generic.List[object]]::new()
    }
    process { foreach ($o in $InputObject) { if ($null -ne $o) { $rows.Add($o) } } }
    end {
        if ($rows.Count -eq 0) { Write-Warning 'Export-IntuneExcel: nothing to export.'; return }
        $names = $rows[0].PSObject.Properties.Name

        # status-aware conditional formatting
        $cond = [System.Collections.Generic.List[object]]::new()
        $good = { param($t) New-ConditionalText -Text $t -BackgroundColor '#D7F2DD' -ConditionalTextColor '#0B6B2E' }
        $bad = { param($t) New-ConditionalText -Text $t -BackgroundColor '#FBD9D3' -ConditionalTextColor '#9C1B0B' }
        $warn = { param($t) New-ConditionalText -Text $t -BackgroundColor '#FFF1C2' -ConditionalTextColor '#7A5A00' }
        $info = { param($t) New-ConditionalText -Text $t -BackgroundColor '#DCE8FB' -ConditionalTextColor '#1B3F78' }
        if ($names -contains 'Status' -or $names -contains 'State' -or $names -contains 'Effective') {
            'installed', 'compliant', 'success', 'OK', 'yes', 'Provisioned', 'approved', 'completed' | ForEach-Object { $cond.Add((& $good $_)) }
            'failed', 'error', 'noncompliant', 'FAILED', 'rejected', 'denied', 'BLOCKED', 'Failure' | ForEach-Object { $cond.Add((& $bad $_)) }
            'pending', 'inGracePeriod', 'needsApproval', 'PendingApproval' | ForEach-Object { $cond.Add((& $warn $_)) }
            'notApplicable', 'notInstalled', 'SKIP' | ForEach-Object { $cond.Add((& $info $_)) }
        }
        if ($names -contains 'Change' -or $names -contains 'Relationship') {
            'Added', 'New', 'Both' | ForEach-Object { $cond.Add((& $good $_)) }
            'Removed', 'Gone', 'Conflict' | ForEach-Object { $cond.Add((& $bad $_)) }
            'OnlyA', 'OnlyB' | ForEach-Object { $cond.Add((& $info $_)) }
        }
        if ($names -contains 'Exclude') { $cond.Add((New-ConditionalText -Text 'True' -BackgroundColor '#FBD9D3' -ConditionalTextColor '#9C1B0B')) }

        $params = @{
            Path = $Path; WorksheetName = $WorksheetName; AutoSize = $true; AutoFilter = $true
            FreezeTopRow = $true; BoldTopRow = $true; TableStyle = 'Medium2'
            TableName = ($WorksheetName -replace '\W', '')
        }
        if ($Append) { $params.Append = $true }
        if ($Title) { $params.Title = $Title; $params.TitleBold = $true; $params.TitleSize = 14 }
        if ($cond.Count) { $params.ConditionalText = $cond.ToArray() }
        if ($Show) { $params.Show = $true }

        $rows | Export-Excel @params
        Write-Verbose "Wrote $($rows.Count) row(s) to $Path [$WorksheetName]"
    }
}
