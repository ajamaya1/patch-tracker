function Backup-IntuneAssignment {
    <#
    .SYNOPSIS
        Snapshot every resource's assignments to a JSON file.

    .DESCRIPTION
        Captures the full assignment set (groups, include/exclude, filters, app
        intent + settings, and the raw Graph assignment objects) for every
        assignable resource, so you can restore it later or diff against it for
        drift. Pair with Restore-IntuneAssignment and Get-IntuneAssignmentDrift.

    .PARAMETER Path
        Where to write the JSON snapshot.

    .PARAMETER Area
        Limit the snapshot to one or more areas.

    .PARAMETER Type
        Limit to one or more resource type keys.

    .PARAMETER AssignedOnly
        Only snapshot resources that currently have assignments.

    .EXAMPLE
        Backup-IntuneAssignment -Path .\intune-assignments-2026-06-25.json

        Full-tenant assignment backup.

    .EXAMPLE
        Backup-IntuneAssignment -Path apps.json -Area Apps -AssignedOnly

        Back up just the app assignments.

    .OUTPUTS
        The snapshot object (also written to -Path).

    .LINK
        Restore-IntuneAssignment
    .LINK
        Get-IntuneAssignmentDrift
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Area,
        [string[]]$Type,
        [switch]$AssignedOnly
    )
    $items = Get-IaInventory -Area $Area -Type $Type -AssignedOnly:$AssignedOnly
    $tenant = try { (Get-MgContext).TenantId } catch { $null }
    $snap = [pscustomobject]@{
        schema    = 'intunetide/assignment-snapshot/1'
        created   = (Get-Date).ToUniversalTime().ToString('o')
        tenant    = $tenant
        count     = $items.Count
        resources = @($items | ForEach-Object { ConvertTo-IaAssignmentSnapshot -Item $_ })
    }
    $snap | ConvertTo-Json -Depth 12 | Set-Content -Path $Path -Encoding utf8
    Write-Verbose "Wrote snapshot of $($items.Count) resource(s) to $Path"
    $snap
}
