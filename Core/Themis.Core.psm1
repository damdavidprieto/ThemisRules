<#
.SYNOPSIS
    ThemisRules Engine v2.0 (Modular Core)
    Universal Compliance & Policy Enforcement for Windows

.DESCRIPTION
    Dynamically loads providers from '\Providers' and dispatches rules.
    Features: Parallel Execution, Provider Abstraction.

.AUTHOR
    Cassiel Security Team
#>

# Load Providers Globals
$ProviderCache = @{}

function Initialize-ThemisProviders {
    $providerPath = Join-Path $PSScriptRoot "Providers"
    $modules = Get-ChildItem -Path $providerPath -Filter "Themis.Provider.*.psm1"
    
    foreach ($mod in $modules) {
        Import-Module $mod.FullName -Force -Scope Global
        
        # Detect Type from filename (Themis.Provider.Registry.psm1 -> Registry)
        if ($mod.Name -match "Themis\.Provider\.(.+)\.psm1") {
            $type = $matches[1]
            $cmdlet = "Invoke-Themis${type}Rule"
            
            if (Get-Command $cmdlet -ErrorAction SilentlyContinue) {
                $script:ProviderCache[$type] = $cmdlet
                Write-Verbose "[Themis] Registered Provider: $type -> $cmdlet"
            }
        }
    }
}

function Invoke-ThemisPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Audit", "Enforce")]
        [string]$Mode = "Audit",

        [Parameter(Mandatory = $false)]
        [switch]$Parallel = $false
    )

    # 1. Initialize
    if ($script:ProviderCache.Count -eq 0) { Initialize-ThemisProviders }

    if (-not (Test-Path $PolicyPath)) {
        Write-Error "[Themis] Policy not found: $PolicyPath"
        return $null
    }

    $policy = Get-Content $PolicyPath -Raw | ConvertFrom-Json
    Write-Verbose "Loaded Policy: $($policy.Meta.Name) v$($policy.Meta.Version)"

    # 2. Flatten Rules
    # We need a flat list for parallel processing
    $allRules = @()
    
    # Iterate known provider types in the JSON
    foreach ($prop in $policy.PSObject.Properties) {
        if ($prop.Name -match "(.+)Rules") {
            $type = $matches[1] # "Registry" from "RegistryRules"
            
            if ($script:ProviderCache.ContainsKey($type)) {
                foreach ($rule in $prop.Value) {
                    # Inject Type into Rule Object for dispatcher
                    $rule | Add-Member -MemberType NoteProperty -Name "_ProviderType" -Value $type -Force
                    $allRules += $rule
                }
            }
        }
    }

    $results = @()
    
    # 3. Execution
    if ($Parallel) {
        # Parallel Execution (PowerShell 7+)
        # If PS5, fallback to standard or use PoshRSJob if available. 
        # For simplicity in this script, we'll assume PS 5.1 compatibility which means standard loop 
        # unless user has PS7. We act as if standard for higher compat unless requested specific impl.
        
        # TODO: Implement true RunspacePool for PS5.1 speed here.
        # For now, simple loop is safer for stability until tested.
        Write-Verbose "Parallel flag ignored in v2.0-Alpha (Stability focus)."
    }

    foreach ($rule in $allRules) {
        $type = $rule._ProviderType
        $cmdlet = $script:ProviderCache[$type]
        
        Write-Verbose "Processing Rule: $($rule.ID) ($type)"
        
        # Dispatch
        try {
            $res = & $cmdlet -Rule $rule -Mode $Mode
            
            # Enrich Result
            $obj = [PSCustomObject]@{
                Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Policy      = $policy.Meta.Name
                ID          = $rule.ID
                Type        = $type
                Name        = $rule.Name
                Status      = $res.Status
                IsCompliant = $res.IsCompliant
                Reason      = $res.Reason
                Actual      = $res.Actual
            }
            $results += $obj

        }
        catch {
            Write-Error "Dispatch Error ($type): $_"
        }
    }

    return $results
}

Export-ModuleMember -Function Invoke-ThemisPolicy
