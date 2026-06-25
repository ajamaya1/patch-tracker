# Microsoft Graph access layer. Every Graph call funnels through Invoke-IaRequest
# so the whole module is unit-testable: Pester mocks Invoke-IaRequest and the
# higher-level helpers (paging, count, assign) come along for free.

$script:IaGraphBase = 'https://graph.microsoft.com/beta'
$script:IaGraphV1   = 'https://graph.microsoft.com/v1.0'

# ---- live call log: every Graph call is recorded here (a ring buffer) so the
# TUI can show a "graph calls" pane and Get-IntuneCallLog can replay it.
$script:IaCallLog     = [System.Collections.Generic.List[object]]::new()
$script:IaCallLogCap  = 1000
$script:IaCallLogOn   = $true
$script:IaCallSink    = $null   # optional scriptblock invoked per call (TUI live stream)

function Add-IaCall {
    param([string]$Method, [string]$Uri, [int]$Status, [double]$Ms, [int]$Count, [string]$ErrorText)
    if (-not $script:IaCallLogOn) { return }
    $short = $Uri -replace '^https://graph\.microsoft\.com', '' -replace '\?.*$', '?…'
    $entry = [pscustomobject]@{
        Time = (Get-Date); Method = $Method; Uri = $short
        Status = $Status; Ms = [math]::Round($Ms); Count = $Count; Error = $ErrorText
    }
    $script:IaCallLog.Add($entry)
    if ($script:IaCallLog.Count -gt $script:IaCallLogCap) { $script:IaCallLog.RemoveAt(0) }
    if ($script:IaCallSink) { try { & $script:IaCallSink $entry } catch { } }
}

function Get-IaCallLogEntries { @($script:IaCallLog.ToArray()) }
function Clear-IaCallLog { $script:IaCallLog.Clear() }
function Set-IaCallSink { param([scriptblock]$Sink) $script:IaCallSink = $Sink }

function Resolve-IaUri {
    param([Parameter(Mandatory)][string]$Path, [switch]$V1)
    if ($Path -match '^https?://') { return $Path }
    $base = if ($V1) { $script:IaGraphV1 } else { $script:IaGraphBase }
    "$base/$($Path.TrimStart('/'))"
}

function Invoke-IaRequest {
    # The single seam over Microsoft.Graph's Invoke-MgGraphRequest. Returns the
    # response as a PSObject (so .value / '@odata.nextLink' are property access).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PATCH', 'DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [object]$Body,
        [hashtable]$Headers
    )
    $params = @{ Method = $Method; Uri = $Uri; OutputType = 'PSObject'; ErrorAction = 'Stop' }
    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 20 -Compress)
        $params.ContentType = 'application/json'
    }
    if ($Headers) { $params.Headers = $Headers }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $resp = Invoke-MgGraphRequest @params
        $sw.Stop()
        $count = if ($resp -and $resp.PSObject.Properties['value']) { @($resp.value).Count } else { 0 }
        Add-IaCall -Method $Method -Uri $Uri -Status 200 -Ms $sw.Elapsed.TotalMilliseconds -Count $count
        return $resp
    } catch {
        $sw.Stop()
        $status = 0
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $status = [int]$_.Exception.Response.StatusCode
        }
        Add-IaCall -Method $Method -Uri $Uri -Status $status -Ms $sw.Elapsed.TotalMilliseconds -Count 0 -ErrorText $_.Exception.Message
        throw
    }
}

function Get-IaCollection {
    # GET a collection, following @odata.nextLink to completion.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [switch]$V1)
    $items = [System.Collections.Generic.List[object]]::new()
    $uri = Resolve-IaUri -Path $Path -V1:$V1
    while ($uri) {
        $resp = Invoke-IaRequest -Method GET -Uri $uri
        if ($resp.value) { foreach ($v in $resp.value) { [void]$items.Add($v) } }
        $uri = $resp.'@odata.nextLink'
    }
    , $items.ToArray()
}

function Get-IaCount {
    # $count endpoint (requires the advanced-query ConsistencyLevel header).
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [switch]$V1)
    try {
        $uri = Resolve-IaUri -Path $Path -V1:$V1
        $r = Invoke-IaRequest -Method GET -Uri $uri -Headers @{ ConsistencyLevel = 'eventual' }
        return [int]$r
    } catch { return -1 }  # unknown (e.g. no permission) — caller must not treat as empty
}

function Invoke-IaAssign {
    # POST the /assign action. The action replaces the whole assignment set, so
    # callers always read-merge-write the complete list.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ListPath,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][hashtable]$Body
    )
    $uri = Resolve-IaUri -Path "$ListPath/$Id/assign"
    Invoke-IaRequest -Method POST -Uri $uri -Body $Body | Out-Null
}
