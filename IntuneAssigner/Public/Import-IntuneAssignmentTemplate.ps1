function Import-IntuneAssignmentTemplate {
    <#
    .SYNOPSIS
        Stamp a device group onto every resource listed in a template.
    .EXAMPLE
        Import-IntuneAssignmentTemplate -Path gold.json -Group "New Store Devices" -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Group
    )
    if (-not (Test-Path $Path)) { throw "Template file not found: $Path" }
    $tmpl = Get-Content -Path $Path -Raw | ConvertFrom-Json
    $g = Resolve-IaGroup -Value $Group
    $keys = @($tmpl.resources | ForEach-Object resource_type | Select-Object -Unique)
    $items = Get-IaInventory -Type $keys

    $commit = $PSCmdlet.ShouldProcess($g.DisplayName, "Apply template '$($tmpl.name)'")
    Invoke-IaTemplateApply -Template $tmpl -Items $items -GroupId $g.Id -GroupName $g.DisplayName -Commit:$commit
}
