# ThemisRules policy engine core.
# Compliance auditing and enforcement for Windows, driven by JSON policies.
#
# Discovers the rule providers loaded from Providers/ and dispatches rules to them.
#
# David Prieto

# Provider registry: rule type (e.g. "Registry") -> command that evaluates it.
$script:ProviderCache = @{}

function Initialize-ThemisProviders {
    <#
    .SYNOPSIS
        Registers the Invoke-Themis<Type>Rule provider functions of this module.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Private function; registers several providers.')]
    [CmdletBinding()]
    param()

    # Providers are the Invoke-Themis<Type>Rule functions dot-sourced from Providers/*.ps1.
    # Only functions defined by this module count: a function with a matching name defined
    # elsewhere in the session must not be able to register itself as a provider.
    $script:ProviderCache = @{}
    $thisModule = $ExecutionContext.SessionState.Module
    foreach ($command in Get-Command -Name 'Invoke-Themis*Rule' -CommandType Function) {
        if ($null -eq $thisModule -or $command.ScriptBlock.Module -ne $thisModule) { continue }
        if ($command.Name -match '^Invoke-Themis(.+)Rule$') {
            $script:ProviderCache[$matches[1]] = $command.Name
            Write-Verbose "[Themis] Registered Provider: $($matches[1]) -> $($command.Name)"
        }
    }
}

function Invoke-ThemisPolicy {
    <#
    .SYNOPSIS
        Checks a JSON policy against this machine and, in Enforce mode, applies it.

    .DESCRIPTION
        Reads the policy and evaluates every rule in its RegistryRules, ServiceRules and
        ProcessRules sections with the matching provider, then returns one result per rule
        with Timestamp, Policy, PolicyPath, ID, Type, Name, MacroLevel, Status, IsCompliant,
        Reason and Actual. Status is Compliant, Non-Compliant, Fixed, Missing*, EnforceFailed
        or Error.
        Audit mode (the default) only reads. Enforce mode changes the system to match the
        policy: it writes registry values, starts, stops, reconfigures or deletes services and
        stops processes. Enforce supports -WhatIf and -Confirm: rules you decline, or all rules
        with -WhatIf, are only audited. Run Enforce elevated for HKLM keys and services.
        A policy runs with your permissions: only use policies from a source you trust.
        Sections without a provider are skipped with a warning.

    .PARAMETER PolicyPath
        Path to the policy JSON file.

    .PARAMETER Mode
        Audit (check only, the default) or Enforce (apply the policy).

    .PARAMETER MacroLevel
        Evaluate only rules up to this hardening level, L1 to L5. Rules without a level are
        always evaluated.

    .PARAMETER Parallel
        Accepted for compatibility with earlier versions; rules always run one after another.

    .EXAMPLE
        Invoke-ThemisPolicy -PolicyPath .\baseline.json

        Audits every rule and returns the results.

    .EXAMPLE
        Invoke-ThemisPolicy -PolicyPath .\baseline.json -Mode Enforce -MacroLevel L1 -WhatIf

        Shows which L1 rules would be enforced, and audits them without changing anything.

    .EXAMPLE
        Invoke-ThemisPolicy -PolicyPath .\baseline.json | Where-Object { -not $_.IsCompliant } | Export-ThemisReport -Path .\gaps.html

        Saves the rules that do not comply as an HTML report.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyPath,

        [ValidateSet('Audit', 'Enforce')]
        [string]$Mode = 'Audit',

        [ValidatePattern('^L[1-5]$')]
        [string]$MacroLevel = $null,

        [switch]$Parallel
    )

    # 1. Initialize
    if ($script:ProviderCache.Count -eq 0) { Initialize-ThemisProviders }

    if (-not (Test-Path -LiteralPath $PolicyPath -PathType Leaf)) {
        Write-Error "[Themis] Policy not found: $PolicyPath"
        return $null
    }

    # -Encoding UTF8: Windows PowerShell 5.1 reads files without a BOM as ANSI otherwise.
    $policy = Get-Content -LiteralPath $PolicyPath -Raw -Encoding UTF8 | ConvertFrom-Json
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

            if (-not $script:ProviderCache.ContainsKey($type)) {
                Write-Warning "[Themis] No provider for '$($prop.Name)'; its rules are skipped."
            }
            else {
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
        Write-Verbose "-Parallel is ignored: rules run sequentially."
    }

    foreach ($rule in $allRules) {
        $type = $rule._ProviderType
        $cmdlet = $script:ProviderCache[$type]

        Write-Verbose "Processing Rule: $($rule.ID) ($type)"

        # Enforce changes the system: each rule asks ShouldProcess, and is only audited when
        # declined or when -WhatIf is used.
        $ruleMode = $Mode
        if ($Mode -eq 'Enforce' -and -not $PSCmdlet.ShouldProcess("$type rule $($rule.ID) ($($rule.Name))", 'Enforce')) {
            $ruleMode = 'Audit'
        }

        try {
            $res = & $cmdlet -Rule $rule -Mode $ruleMode

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
