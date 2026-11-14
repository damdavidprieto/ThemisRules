<#
.SYNOPSIS
    Themis Registry Provider
.DESCRIPTION
    Handles 'Registry' type rules for Themis Engine.
#>

function Test-ThemisRegistryPath {
    # True when Path resolves to the Registry provider (HKLM:, HKCU:, Registry::..., or any
    # PSDrive backed by it). File system, environment and other providers are rejected.
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        $provider = $null
        $drive = $null
        $null = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path, [ref]$provider, [ref]$drive)
        return ($null -ne $provider -and $provider.Name -eq 'Registry')
    }
    catch {
        return $false
    }
}

function Invoke-ThemisRegistryRule {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode # Audit, Enforce
    )

    $result = [ordered]@{
        Status      = "Unknown"
        IsCompliant = $false
        Reason      = ""
        Actual      = $null
    }

    # Registry rules may only touch the registry. Without this check a policy could point
    # Path at the file system and Enforce would create files or change file attributes.
    if (-not (Test-ThemisRegistryPath -Path $Rule.Path)) {
        $result.Status = "Error"
        $result.Reason = "Path is not a registry path: '$($Rule.Path)'. Use a registry drive such as HKLM: or HKCU:."
        return $result
    }
    if ([string]::IsNullOrWhiteSpace($Rule.ValueName)) {
        $result.Status = "Error"
        $result.Reason = "Registry rule has no ValueName."
        return $result
    }

    try {
        if (-not (Test-Path -LiteralPath $Rule.Path)) {
            $result.Status = "MissingKey"
            $result.Reason = "Key path not found: $($Rule.Path)"

            if ($Mode -eq "Enforce") {
                New-Item -Path $Rule.Path -Force | Out-Null
            }
            else {
                return $result
            }
        }

        $reg = Get-ItemProperty -LiteralPath $Rule.Path -Name $Rule.ValueName -ErrorAction SilentlyContinue
        
        if ($null -eq $reg) {
            $result.Status = "MissingValue"
            $result.Reason = "Value '$($Rule.ValueName)' not found."
        }
        else {
            $currentValue = $reg.$($Rule.ValueName)
            $result.Actual = $currentValue

            $match = $false
            # Enhanced Type handling
            switch ($Rule.Type) {
                "DWord" { if ([long]$currentValue -eq [long]$Rule.Value) { $match = $true } }
                "QWord" { if ([long]$currentValue -eq [long]$Rule.Value) { $match = $true } }
                "String" { if ("$currentValue" -eq "$($Rule.Value)") { $match = $true } }
                "MultiString" { 
                    # Compare arrays
                    if ($null -ne $currentValue -and ($currentValue | Sort-Object) -join ',' -eq ($Rule.Value | Sort-Object) -join ',') { 
                        $match = $true 
                    } 
                }
                Default { if ("$currentValue" -eq "$($Rule.Value)") { $match = $true } } # Fallback
            }

            if ($match) {
                $result.Status = "Compliant"
                $result.IsCompliant = $true
                $result.Reason = "Value matches expected configuration."
            }
            else {
                $result.Status = "Non-Compliant"
                $result.Reason = "Expected '$($Rule.Value)' but found '$currentValue'."
            }
        }

        # ENFORCEMENT
        if ($Mode -eq "Enforce" -and -not $result.IsCompliant) {
            try {
                $ruleType = if ($Rule.Type) { $Rule.Type } else { "String" }
                Set-ItemProperty -LiteralPath $Rule.Path -Name $Rule.ValueName -Value $Rule.Value -Type $ruleType -Force -ErrorAction Stop
                $result.Status = "Fixed"
                $result.IsCompliant = $true
                $result.Reason = "Remediated by Registry Provider."
            }
            catch {
                $result.Status = "EnforceFailed"
                $result.Reason = "Failed to set value: $_"
            }
        }

    }
    catch {
        $result.Status = "Error"
        $result.Reason = "Provider Error: $_"
    }

    return $result
}

