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
    $providerPath = Join-Path $PSScriptRoot "..\Providers"
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
    <#
    .SYNOPSIS
        Executes a security policy with optional level-based filtering.
    
    .PARAMETER PolicyPath
        Path to the policy JSON file.
    
    .PARAMETER Mode
        Execution mode: Audit (check only) or Enforce (apply changes).
    
    .PARAMETER MacroLevel
        Filter rules by hardening level (L1-L5). Only rules <= specified level are evaluated.
        Example: -MacroLevel "L1" evaluates only L1 rules.
    
    .PARAMETER Parallel
        Enable parallel execution (experimental).
    
    .EXAMPLE
        Invoke-ThemisPolicy -PolicyPath ".\system_security.json" -Mode Audit -MacroLevel "L1"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Audit", "Enforce")]
        [string]$Mode = "Audit",

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^L[1-5]$')]
        [string]$MacroLevel = $null,

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
    $policyName = if ($policy.Meta.Name) { $policy.Meta.Name } else { [System.IO.Path]::GetFileNameWithoutExtension($PolicyPath) }
    $policyVersion = if ($policy.Meta.Version) { $policy.Meta.Version } else { "1.0.0" }
    
    Write-Verbose "Loaded Policy: $policyName v$policyVersion"
    if ($MacroLevel) {
        Write-Verbose "Filtering by MacroLevel: $MacroLevel"
    }

    # 2. Flatten Rules with MacroLevel Filtering
    $allRules = @()
    $targetLevel = if ($MacroLevel) { [int]($MacroLevel -replace 'L', '') } else { 999 }
    
    # Iterate known provider types in the JSON
    foreach ($prop in $policy.PSObject.Properties) {
        if ($prop.Name -match "(.+)Rules") {
            $type = $matches[1] # "Registry" from "RegistryRules"
            
            if ($script:ProviderCache.ContainsKey($type)) {
                foreach ($rule in $prop.Value) {
                    # Apply MacroLevel filter
                    $ruleLevel = 999 # Default: include if no MacroLevel specified
                    if ($rule.MacroLevel -and $rule.MacroLevel -match '^L([1-5])$') {
                        $ruleLevel = [int]$matches[1]
                    }
                    
                    # Only include rules <= target level
                    if ($ruleLevel -le $targetLevel) {
                        # Inject Type and Metadata into Rule Object
                        $rule | Add-Member -MemberType NoteProperty -Name "_ProviderType" -Value $type -Force
                        $rule | Add-Member -MemberType NoteProperty -Name "_PolicyName" -Value $policyName -Force
                        $rule | Add-Member -MemberType NoteProperty -Name "_PolicyPath" -Value $PolicyPath -Force
                        $allRules += $rule
                    }
                    else {
                        Write-Verbose "Skipping rule $($rule.ID) (Level: $($rule.MacroLevel), Target: $MacroLevel)"
                    }
                }
            }
        }
    }

    Write-Verbose "Total rules after filtering: $($allRules.Count)"
    $results = @()
    
    # 3. Execution
    if ($Parallel) {
        Write-Verbose "Parallel flag ignored in v1.2.0 (Stability focus)."
    }

    foreach ($rule in $allRules) {
        $type = $rule._ProviderType
        $cmdlet = $script:ProviderCache[$type]
        
        Write-Verbose "Processing Rule: $($rule.ID) ($type)"
        
        # Dispatch
        try {
            $res = & $cmdlet -Rule $rule -Mode $Mode
            
            # Enrich Result with Enhanced Metadata
            $obj = [PSCustomObject]@{
                Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Policy      = $rule._PolicyName
                PolicyPath  = $rule._PolicyPath
                ID          = $rule.ID
                Type        = $type
                Name        = $rule.Name
                MacroLevel  = $rule.MacroLevel
                Status      = $res.Status
                IsCompliant = $res.IsCompliant
                Reason      = $res.Reason
                Actual      = $res.Actual
            }
            $results += $obj

        }
        catch {
            Write-Error "Dispatch Error ($type / $($rule.ID)): $_"
        }
    }

    return $results
}

Export-ModuleMember -Function Invoke-ThemisPolicy
