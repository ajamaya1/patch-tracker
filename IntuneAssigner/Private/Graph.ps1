# Microsoft Graph access layer. Every Graph call funnels through Invoke-IaRequest
# so the whole module is unit-testable: Pester mocks Invoke-IaRequest and the
# higher-level helpers (paging, count, assign) come along for free.

$script:IaGraphBase = 'https://graph.microsoft.com/beta'
$script:IaGraphV1   = 'https://graph.microsoft.com/v1.0'

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
    Invoke-MgGraphRequest @params
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
