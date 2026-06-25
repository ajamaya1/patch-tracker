# Group / assignment-filter resolution and membership lookups, with caching.
# This is what makes assignments readable: Graph returns bare GUIDs everywhere.

$script:IaGroupCache  = @{}   # id -> [pscustomobject]{ Id, DisplayName, MembershipType }
$script:IaGroupByName = @{}   # lower(name) -> @(group)
$script:IaFilterCache = @{}   # id -> name
$script:IaFiltersLoaded = $false
$script:IaCountCache  = @{}   # id -> member count

function Reset-IaDirectoryCache {
    $script:IaGroupCache  = @{}
    $script:IaGroupByName = @{}
    $script:IaFilterCache = @{}
    $script:IaFiltersLoaded = $false
    $script:IaCountCache  = @{}
}

function Test-IaGuid {
    param([string]$Value)
    $g = [guid]::Empty
    [guid]::TryParse($Value, [ref]$g)
}

# ---- assignment filters ----
function Initialize-IaFilters {
    if ($script:IaFiltersLoaded) { return }
    foreach ($f in (Get-IaCollection -Path 'deviceManagement/assignmentFilters?$select=id,displayName')) {
        $script:IaFilterCache[$f.id] = $f.displayName
    }
    $script:IaFiltersLoaded = $true
}
function Get-IaFilterName {
    param([string]$Id)
    if (-not $Id) { return $null }
    Initialize-IaFilters
    $script:IaFilterCache[$Id]
}
function Get-IaFilterIdByName {
    param([string]$Name)
    if (-not $Name) { return $null }
    Initialize-IaFilters
    ($script:IaFilterCache.GetEnumerator() | Where-Object { $_.Value -and $_.Value.ToLower() -eq $Name.ToLower() } | Select-Object -First 1).Key
}

function Get-IaFilterList {
    # All assignment filters as { Id, Name } objects (for the TUI picker).
    Initialize-IaFilters
    $script:IaFilterCache.GetEnumerator() |
        ForEach-Object { [pscustomobject]@{ Id = $_.Key; Name = $_.Value } } |
        Sort-Object Name
}

# ---- group name resolution ----
function Add-IaGroupToCache {
    param([Parameter(Mandatory)][object]$Group)
    $ref = [pscustomobject]@{
        Id             = $Group.id
        DisplayName    = $Group.displayName
        MembershipType = if ($Group.membershipRule) { 'dynamic' } else { 'assigned' }
    }
    $script:IaGroupCache[$ref.Id] = $ref
    $k = ($ref.DisplayName ?? '').ToLower()
    if (-not $script:IaGroupByName.ContainsKey($k)) { $script:IaGroupByName[$k] = @() }
    if ($ref.Id -notin ($script:IaGroupByName[$k] | ForEach-Object Id)) {
        $script:IaGroupByName[$k] += $ref
    }
    $ref
}

function Resolve-IaGroupName {
    param([string]$Id)
    if (-not $Id) { return $null }
    if ($script:IaGroupCache.ContainsKey($Id)) { return $script:IaGroupCache[$Id].DisplayName }
    try {
        $g = Invoke-IaRequest -Method GET -Uri (Resolve-IaUri -V1 -Path "groups/$Id`?`$select=id,displayName,membershipRule")
        return (Add-IaGroupToCache -Group $g).DisplayName
    } catch {
        # Deleted / inaccessible — record a marker so reports show it as orphaned.
        $stub = $Id.Substring(0, [Math]::Min(8, $Id.Length))
        $script:IaGroupCache[$Id] = [pscustomobject]@{ Id = $Id; DisplayName = "(unresolved $stub…)"; MembershipType = $null }
        return $script:IaGroupCache[$Id].DisplayName
    }
}

function Resolve-IaGroupNames {
    param([string[]]$Ids)
    foreach ($id in ($Ids | Where-Object { $_ } | Select-Object -Unique)) {
        if (-not $script:IaGroupCache.ContainsKey($id)) { [void](Resolve-IaGroupName -Id $id) }
    }
}

function Resolve-IaGroup {
    # Resolve a CLI/TUI group argument that may be a GUID or a display name.
    param([Parameter(Mandatory)][string]$Value)
    if (Test-IaGuid $Value) {
        $name = Resolve-IaGroupName -Id $Value
        return [pscustomobject]@{ Id = $Value; DisplayName = $name }
    }
    $key = $Value.ToLower()
    if (-not $script:IaGroupByName.ContainsKey($key)) {
        $esc = $Value.Replace("'", "''")
        $matches = Get-IaCollection -V1 -Path ("groups?`$filter=displayName eq '$esc'&`$select=id,displayName,membershipRule")
        foreach ($m in $matches) { [void](Add-IaGroupToCache -Group $m) }
    }
    $found = $script:IaGroupByName[$key]
    if (-not $found) { throw "No group found matching '$Value'." }
    if ($found.Count -gt 1) {
        $list = ($found | ForEach-Object { "$($_.DisplayName) ($($_.Id))" }) -join ', '
        throw "'$Value' is ambiguous — matches: $list"
    }
    [pscustomobject]@{ Id = $found[0].Id; DisplayName = $found[0].DisplayName }
}

# ---- membership ----
function Get-IaGroupMemberCount {
    param([Parameter(Mandatory)][string]$Id)
    if ($script:IaCountCache.ContainsKey($Id)) { return $script:IaCountCache[$Id] }
    $n = Get-IaCount -V1 -Path "groups/$Id/members/`$count"
    $script:IaCountCache[$Id] = $n
    $n
}

function Get-IaSubjectGroups {
    # Resolve a user (UPN/id) or device (name/id) to its transitive group set.
    param(
        [Parameter(Mandatory)][ValidateSet('user', 'device')][string]$Kind,
        [Parameter(Mandatory)][string]$Value
    )
    if ($Kind -eq 'user') {
        $u = Invoke-IaRequest -Method GET -Uri (Resolve-IaUri -V1 -Path "users/$([uri]::EscapeDataString($Value))?`$select=id,displayName,userPrincipalName")
        $display = if ($u.displayName) { $u.displayName } else { $u.userPrincipalName }
        $oid = $u.id
        $path = "users/$oid/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName"
    } else {
        $dev = Resolve-IaDevice -Value $Value
        $display = $dev.DisplayName
        $oid = $dev.Id
        $path = "devices/$oid/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName"
    }
    $groups = Get-IaCollection -V1 -Path $path
    $ids = foreach ($g in $groups) { [void](Add-IaGroupToCache -Group $g); $g.id }
    [pscustomobject]@{ Display = $display; GroupIds = [string[]]$ids }
}

function Resolve-IaDevice {
    param([Parameter(Mandatory)][string]$Value)
    if (Test-IaGuid $Value) {
        try {
            $d = Invoke-IaRequest -Method GET -Uri (Resolve-IaUri -V1 -Path "devices/$Value`?`$select=id,displayName")
            return [pscustomobject]@{ Id = $d.id; DisplayName = $d.displayName }
        } catch { }
    }
    $esc = $Value.Replace("'", "''")
    $matches = Get-IaCollection -V1 -Path ("devices?`$filter=displayName eq '$esc'&`$select=id,displayName,deviceId")
    if ($matches.Count -eq 1) { return [pscustomobject]@{ Id = $matches[0].id; DisplayName = $matches[0].displayName } }
    if (-not $matches) { throw "No Entra device found matching '$Value'." }
    throw "'$Value' matches multiple devices: $((($matches | ForEach-Object displayName) -join ', '))"
}
