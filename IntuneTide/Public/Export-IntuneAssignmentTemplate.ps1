function Export-IntuneAssignmentTemplate {
    <#
    .SYNOPSIS
        Capture everything a group is assigned to as a reusable JSON template.
    .EXAMPLE
        Export-IntuneAssignmentTemplate -Group "Gold Build" -Name gold -Path gold.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Group,
        [Parameter(Mandatory)][string]$Name,
        [string]$Description = '',
        [string]$Path
    )
    $g = Resolve-IaGroup -Value $Group
    $items = Get-IaInventory -AssignedOnly
    $tmpl = New-IaTemplateFromGroup -Items $items -GroupId $g.Id -Name $Name -Description $Description
    if ($Path) {
        $tmpl | ConvertTo-Json -Depth 8 | Set-Content -Path $Path -Encoding utf8
        Write-Verbose "Template '$Name' with $($tmpl.resources.Count) resource(s) → $Path"
    }
    $tmpl
}
