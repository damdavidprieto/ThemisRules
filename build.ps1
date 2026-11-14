<#
.SYNOPSIS
    Builds ThemisRules into output/ThemisRules, ready to install or publish.

.DESCRIPTION
    Runs PSScriptAnalyzer with PSScriptAnalyzerSettings.psd1 and the Pester tests, then copies
    only the files the module needs at runtime into output/ThemisRules and validates the
    result. Publish that folder, never the repository root, so tests, docs and .git never reach
    the PowerShell Gallery.

.PARAMETER InstallDependencies
    Install Pester 5 and PSScriptAnalyzer for the current user first.

.PARAMETER SkipAnalysis
    Do not run PSScriptAnalyzer.

.PARAMETER SkipTests
    Do not run the Pester tests.

.EXAMPLE
    ./build.ps1 -InstallDependencies

.EXAMPLE
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
$testsPath = Join-Path $PSScriptRoot 'Tests'
$outputDir = Join-Path $PSScriptRoot "output/$moduleName"

# Files and folders the module needs at runtime.
$runtimeItems = @(
    "$moduleName.psd1"
    "$moduleName.psm1"
    'LICENSE'
    'README.md'
    'Core'
    'Providers'
    'Public'
    'Baselines'
    'Schema'
)

if ($InstallDependencies) {
    Install-Module Pester -MinimumVersion 5.0.0 -MaximumVersion 5.99.99 -Force -SkipPublisherCheck -Scope CurrentUser
    Install-Module PSScriptAnalyzer -Force -SkipPublisherCheck -Scope CurrentUser
}

if (-not $SkipAnalysis) {
    Write-Host 'Running PSScriptAnalyzer...' -ForegroundColor Cyan
    $settings = Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'
    $sources = $runtimeItems | ForEach-Object { Join-Path $PSScriptRoot $_ } |
        Get-ChildItem -Recurse -Include '*.ps1', '*.psm1', '*.psd1' -File
    # PSScriptAnalyzer 1.2x can throw a NullReferenceException the first time it runs its rules
    # in a new process; the same call succeeds when repeated, so retry once.
    $issues = foreach ($source in $sources) {
        try { Invoke-ScriptAnalyzer -Path $source.FullName -Settings $settings -ErrorAction Stop }
        catch { if ($_.Exception.Message -match 'Object reference') { Invoke-ScriptAnalyzer -Path $source.FullName -Settings $settings } else { throw } }
    }
    if ($issues) {
        $issues | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize -Wrap | Out-Host
        throw "PSScriptAnalyzer found $(@($issues).Count) issue(s)."
    }
}

if (-not $SkipTests) {
    Write-Host 'Running Pester tests...' -ForegroundColor Cyan
    $config = New-PesterConfiguration
    $config.Run.Path = $testsPath
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
    $source = Join-Path $PSScriptRoot $item
    $destination = Join-Path $outputDir $item
    New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
    Copy-Item -Path $source -Destination $destination -Recurse -Force
}

$manifest = Test-ModuleManifest -Path (Join-Path $outputDir "$moduleName.psd1")
$forbidden = '.git', '.github', 'tests', 'docs', 'examples', 'logs', 'output', 'user'
$unexpected = @(Get-ChildItem $outputDir -Force | Where-Object { $_.Name -in $forbidden }) +
    @(Get-ChildItem $outputDir -Recurse -Force -File | Where-Object { $_.Extension -in '.log', '.nupkg' })
if ($unexpected) {
    throw "Build output contains files that must not be published: $($unexpected.FullName -join ', ')"
}

Write-Host "Built $moduleName $($manifest.Version) in $outputDir" -ForegroundColor Green
