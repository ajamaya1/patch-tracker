function Get-IntuneCallLog {
    <#
    .SYNOPSIS
        Show the Microsoft Graph calls TIDE has made this session.

    .DESCRIPTION
        Every Graph request flows through one seam that records the method, URL
        (host trimmed), HTTP status, duration in ms, and returned item count.
        This is the data behind the TUI's "graph calls" pane — use it from the
        cmdline to see exactly what the tool is doing (great for debugging,
        learning the Graph endpoints, or proving least-privilege reads).

    .PARAMETER Tail
        Only the most recent N calls.

    .PARAMETER Errors
        Only calls that failed (non-2xx).

    .EXAMPLE
        Get-IntuneAssignment -Type mobileApps | Out-Null
        Get-IntuneCallLog -Tail 10 | Format-Table

        Run something, then see the last 10 Graph calls it made.

    .OUTPUTS
        PSCustomObject: Time, Method, Uri, Status, Ms, Count, Error.

    .LINK
        Clear-IntuneCallLog
    #>
    [CmdletBinding()]
    param([int]$Tail, [switch]$Errors)
    $log = @(Get-IaCallLogEntries)
    if ($Errors) { $log = $log | Where-Object { $_.Status -lt 200 -or $_.Status -ge 300 } }
    if ($Tail -and $Tail -gt 0) { $log = $log | Select-Object -Last $Tail }
    $log
}

function Clear-IntuneCallLog {
    <#
    .SYNOPSIS
        Clear the in-memory Graph call log.
    .EXAMPLE
        Clear-IntuneCallLog
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess('Graph call log', 'Clear')) { Clear-IaCallLog }
}
