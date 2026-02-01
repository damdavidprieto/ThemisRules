<#
.SYNOPSIS
    Compila y Publica ThemisRules en PowerShell Gallery
.DESCRIPTION
    1. Verifica que el modulo sea valido.
    2. Verifica NuGet.
    3. Publica usando la API Key proporcionada.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ApiKey
)

$modulePath = Convert-Path "$PSScriptRoot\.."
Write-Host "Preparando publicacion para: $modulePath" -ForegroundColor Cyan

# 1. Validar Manifiesto
Write-Host "1. Validando Modulo..." -ForegroundColor Yellow
$manifest = Test-ModuleManifest -Path "$modulePath\ThemisRules.psd1" -ErrorAction Stop
if (-not $manifest) {
    Write-Error "El manifiesto no es valido."
    exit 1
}

# 2. Publicar
Write-Host "2. Publicando a PSGallery..." -ForegroundColor Yellow
try {
    Publish-Module -Path $modulePath -NuGetApiKey $ApiKey -Verbose
    Write-Host "[OK] Publicado exitosamente!" -ForegroundColor Green
}
catch {
    Write-Error "Error publicando: $_"
}
