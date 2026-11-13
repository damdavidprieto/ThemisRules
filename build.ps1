<#
.SYNOPSIS
    Builds ThemisRules into output/ThemisRules, ready to install or publish.

.DESCRIPTION
    Runs PSScriptAnalyzer and the Pester tests, then copies only the files the module
    needs at runtime into output/ThemisRules and validates the result. Publish that folder,
    never the repository root, so tests and .git never reach the Gallery.

.EXAMPLE
    ./build.ps1
    ./build.ps1 -SkipTests
#>
[CmdletBinding()]
param(
    [switch]$InstallDependencies,
    [switch]$SkipAnalysis,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$moduleName = 'ThemisRules'
$outputDir = Join-Path $PSScriptRoot "output/$moduleName"

# Files and folders the module needs at runtime, plus the policy schema and examples.
$runtimeItems = @(
    "$moduleName.psd1",
    "$moduleName.psm1",
    'LICENSE',
    'README.md',
    'Core',
    'Providers',
    'Public',
    'Schema',
    'Examples'
)

if ($InstallDependencies) {
    Install-Module Pester -MinimumVersion 5.0.0 -Force -SkipPublisherCheck -Scope CurrentUser
    Install-Module PSScriptAnalyzer -Force -SkipPublisherCheck -Scope CurrentUser
}

if (-not $SkipAnalysis) {
    Write-Host 'Running PSScriptAnalyzer...' -ForegroundColor Cyan
    $issues = Invoke-ScriptAnalyzer -Path $PSScriptRoot -Recurse -Severity Error
    if ($issues) {
        $issues | Format-Table -AutoSize
        throw "PSScriptAnalyzer found $($issues.Count) error(s)."
    }
}

if (-not $SkipTests) {
    Write-Host 'Running Pester tests...' -ForegroundColor Cyan
    $config = New-PesterConfiguration
    $config.Run.Path = Join-Path $PSScriptRoot 'Tests'
    $config.Run.PassThru = $true
    $config.Output.Verbosity = 'Normal'
    $result = Invoke-Pester -Configuration $config
    if ($result.FailedCount -gt 0) {
        throw "$($result.FailedCount) test(s) failed."
    }
}

Write-Host "Building $outputDir..." -ForegroundColor Cyan
if (Test-Path $outputDir) { Remove-Item $outputDir -Recurse -Force }
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

foreach ($item in $runtimeItems) {
    Copy-Item -Path (Join-Path $PSScriptRoot $item) -Destination (Join-Path $outputDir $item) -Recurse -Force
}

$manifest = Test-ModuleManifest -Path (Join-Path $outputDir "$moduleName.psd1")
$unexpected = Get-ChildItem $outputDir -Recurse -Force | Where-Object { $_.Name -in '.git', '.github', 'Tests' }
if ($unexpected) {
    throw "Build output contains files that must not be published: $($unexpected.FullName -join ', ')"
}

Write-Host "Built $moduleName $($manifest.Version) in $outputDir" -ForegroundColor Green
