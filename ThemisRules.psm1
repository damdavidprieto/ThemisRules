# ThemisRules - JSON policy engine for Windows compliance auditing and enforcement.
#
# Every file is dot-sourced into this module's scope, so the engine, the providers and the
# public functions share one scope and only the public functions are exported.

foreach ($folder in 'Core', 'Providers', 'Public') {
    foreach ($file in Get-ChildItem -Path (Join-Path $PSScriptRoot $folder) -Filter '*.ps1' | Sort-Object Name) {
        . $file.FullName
    }
}

Initialize-ThemisProviders

# Keep in sync with FunctionsToExport in ThemisRules.psd1 (Tests/QA checks it).
Export-ModuleMember -Function 'Invoke-ThemisPolicy', 'Export-ThemisReport', 'Get-ThemisBaseline', 'Get-ThemisProvider', 'New-ThemisPolicy' -Alias 'Get-ThemisProviders'
