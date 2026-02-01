# Loader Script for ThemisRules

$publicPath = Join-Path $PSScriptRoot "Public"
$corePath = Join-Path $PSScriptRoot "Core"

# 1. Load Core
Import-Module (Join-Path $corePath "Themis.Core.psm1") -Force -Scope Global

# 2. Load Public Functions
Get-ChildItem -Path $publicPath -Filter "*.ps1" | ForEach-Object {
    . $_.FullName
}

# 3. Export Everything
Export-ModuleMember -Function Invoke-ThemisPolicy, Get-ThemisProviders, New-ThemisPolicy
