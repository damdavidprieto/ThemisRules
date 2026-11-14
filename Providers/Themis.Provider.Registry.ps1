# Themis Registry Provider
# Handles 'Registry' type rules for Themis Engine.

function Test-ThemisRegistryPath {
    [CmdletBinding()]
    [OutputType([bool])]
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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', '', Justification = 'Set-ItemProperty -Type is a dynamic parameter of the Registry provider; the compatibility profiles only list static parameters.')]
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
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
            if ($null -ne $Rule.Default -and (Test-ThemisValue -Actual $Rule.Default -Rule $Rule).Match) {
                $result.Status = "Compliant"
                $result.IsCompliant = $true
                $result.Reason = "Not set; the Windows default ($($Rule.Default)) meets the rule."
                $result.Actual = "(default) $($Rule.Default)"
                return $result
            }
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

        if ($null -eq $reg -and $null -ne $Rule.Default -and (Test-ThemisValue -Actual $Rule.Default -Rule $Rule).Match) {
            # Not set, but the value Windows uses when it is missing already meets the rule.
            $result.Status = "Compliant"
            $result.IsCompliant = $true
            $result.Reason = "Not set; the Windows default ($($Rule.Default)) meets the rule."
            $result.Actual = "(default) $($Rule.Default)"
            return $result
        }
        elseif ($null -eq $reg) {
            $result.Status = "MissingValue"
            $result.Reason = "Value '$($Rule.ValueName)' not found."
        }
        else {
            $currentValue = $reg.$($Rule.ValueName)
            $result.Actual = $currentValue

            if ($Rule.Type -eq 'MultiString') {
                $expected = (@($Rule.Value) | Sort-Object) -join ','
                $check = @{ Match = ($null -ne $currentValue -and ((@($currentValue) | Sort-Object) -join ',') -eq $expected); Expected = $expected }
            }
            else {
                # Equal by default; AtLeast, AtMost and Between for numeric values.
                $check = Test-ThemisValue -Actual $currentValue -Rule $Rule
            }

            if ($check.Match) {
                $result.Status = "Compliant"
                $result.IsCompliant = $true
                $result.Reason = "Value is $currentValue (required: $($check.Expected))."
            }
            else {
                $result.Status = "Non-Compliant"
                $result.Reason = "Expected $($check.Expected) but found '$currentValue'."
            }
        }

        # ENFORCEMENT
        if ($Mode -eq "Enforce" -and -not $result.IsCompliant) {
            try {
                $ruleType = if ($Rule.Type) { $Rule.Type } else { "String" }
                Set-ItemProperty -LiteralPath $Rule.Path -Name $Rule.ValueName -Value $Rule.Value -Type $ruleType -Force -ErrorAction Stop
                $result.Status = "Fixed"
                $result.IsCompliant = $true
                $result.Reason = "Value set to $($Rule.Value)."
                $result.Actual = (Get-ItemProperty -LiteralPath $Rule.Path -Name $Rule.ValueName -ErrorAction SilentlyContinue).$($Rule.ValueName)
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
