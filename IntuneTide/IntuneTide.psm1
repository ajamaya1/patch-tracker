# Module loader: dot-source every Private helper then every Public cmdlet, and
# export only the public surface. Keeping one function per file makes the module
# easy to navigate and unit-test.

$Private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue)
$Public  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in @($Private + $Public)) {
    try { . $file.FullName }
    catch { throw "Failed to load $($file.FullName): $_" }
}

# Short launch alias: `tide` opens the TUI.
Set-Alias -Name tide -Value Start-IntuneTide
Export-ModuleMember -Function $Public.BaseName -Alias tide
