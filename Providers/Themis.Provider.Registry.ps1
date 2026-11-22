# Themis Registry Provider
# Handles 'Registry' type rules for Themis Engine.
#
#   Path         Key (HKLM:\..., HKCU:\..., Registry::...). A '*' in the last segment matches every
#                subkey with that pattern, and each of them must comply.
#   ValueName    Value name.
#   Value        Required value. Type: DWord, QWord, String (default), ExpandString, MultiString or Binary.
#   Comparison   Equal (default), AtLeast, AtMost, Between (Min/Max) or In (Value is a list).
#   WriteValue   What Enforce writes when it differs from Value (needed for Between and In).
#   Default      Value Windows uses when the value is missing: a missing value is compliant if it meets the rule.
#   Ensure       Absent: the value must not exist. With MatchValue, only that value is removed.
# DWORD and QWORD values are compared as unsigned numbers (0xFFFFFFFF is 4294967295, not -1).

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

function Resolve-ThemisRegistryKey {
    <#
    .SYNOPSIS
        The keys a rule path refers to: the path itself, or every subkey matching a '*' in the last segment.
    #>
    [CmdletBinding()]
    [OutputType([string[]], [string])]
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path -notmatch '\*') { return $Path }
    $parent = Split-Path -Path $Path -Parent
    $leaf = Split-Path -Path $Path -Leaf
    if ($parent -match '\*') { throw "Only the last segment of a registry path can contain '*': $Path" }
    # Subkey names are enumerated without opening each subkey, so one that cannot be read is
    # still listed (and reported) instead of being skipped silently.
    $key = Get-Item -LiteralPath $parent -ErrorAction SilentlyContinue
    if (-not $key) { return }
    try { $names = $key.GetSubKeyNames() } finally { $key.Close() }
    return ($names | Where-Object { $_ -like $leaf } | ForEach-Object { Join-Path $parent $_ })
}

function Get-ThemisRegistryState {
    <#
    .SYNOPSIS
        Reads one value: @{ Path; KeyExists; Exists; Value; Kind; Readable }.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$ValueName)

    $state = [ordered]@{ Path = $Path; KeyExists = $false; Exists = $false; Value = $null; Kind = $null; Readable = $true }
    $err = $null
    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue -ErrorVariable err
    if (-not $key) {
        if (@($err | Where-Object { $_.Exception -is [System.Security.SecurityException] -or $_.Exception -is [System.UnauthorizedAccessException] -or $_.CategoryInfo.Category -eq 'PermissionDenied' }).Count) {
            $state.Readable = $false
        }
        return $state
    }
    $state.KeyExists = $true
    try {
        if ($key.GetValueNames() -contains $ValueName) {
            $state.Exists = $true
            $value = $key.GetValue($ValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $state.Kind = [string]$key.GetValueKind($ValueName)
            # .NET returns DWORD and QWORD as signed numbers; compare them as Windows shows them.
            if ($state.Kind -eq 'DWord' -and $value -is [int] -and $value -lt 0) { $value = [int64]$value + 4294967296 }
            if ($state.Kind -eq 'QWord' -and $value -is [long] -and $value -lt 0) { $value = [decimal]$value + [decimal]18446744073709551616 }
            $state.Value = $value
        }
    }
    catch [System.Security.SecurityException], [System.UnauthorizedAccessException] { $state.Readable = $false }
    finally { $key.Close() }
    return $state
}

function Test-ThemisRegistryState {
    <#
    .SYNOPSIS
        Whether one value meets the rule: @{ Match; Expected }.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory = $true)]$Rule, [Parameter(Mandatory = $true)]$State)

    if ($Rule.Ensure -eq 'Absent') {
        if (-not $State.Exists) { return @{ Match = $true; Expected = 'absent' } }
        if ($Rule.PSObject.Properties['MatchValue']) {
            $same = (Test-ThemisValue -Actual $State.Value -Rule ([pscustomobject]@{ Value = $Rule.MatchValue })).Match
            return @{ Match = -not $same; Expected = "absent or not $($Rule.MatchValue)" }
        }
        return @{ Match = $false; Expected = 'absent' }
    }
    if (-not $State.Exists) {
        if ($null -ne $Rule.Default) {
            $check = Test-ThemisValue -Actual $Rule.Default -Rule $Rule
            return @{ Match = $check.Match; Expected = $check.Expected; ByDefault = $true }
        }
        return @{ Match = $false; Expected = "$($Rule.Value)" }
    }
    if ($Rule.Type -eq 'MultiString') {
        $expected = (@($Rule.Value) | Sort-Object) -join ','
        return @{ Match = ((@($State.Value) | Sort-Object) -join ',') -eq $expected; Expected = $expected }
    }
    return (Test-ThemisValue -Actual $State.Value -Rule $Rule)
}

function ConvertTo-ThemisRegistryData {
    <#
    .SYNOPSIS
        Converts a value from a policy to the .NET type the registry expects for a value kind.
    #>
    [CmdletBinding()]
    [OutputType([int], [long], [string[]], [byte[]], [string])]
    param($Value, [string]$Kind)

    switch ($Kind) {
        'DWord' { $n = [decimal]"$Value"; if ($n -gt [int]::MaxValue) { $n -= 4294967296 }; return [int]$n }
        'QWord' { $n = [decimal]"$Value"; if ($n -gt [long]::MaxValue) { $n -= [decimal]18446744073709551616 }; return [long]$n }
        'MultiString' { return [string[]]@($Value) }
        'Binary' { return [byte[]]@($Value) }
        default { return [string]$Value }
    }
}

function Invoke-ThemisRegistryRule {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', '', Justification = 'New-ItemProperty -PropertyType is a dynamic parameter of the Registry provider; the compatibility profiles only list static parameters.')]
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
    if ("$($Rule.Comparison)" -in 'Between', 'In' -and $Rule.Ensure -ne 'Absent' -and $null -eq $Rule.WriteValue -and $Mode -eq 'Enforce') {
        $result.Status = "Error"
        $result.Reason = "A $($Rule.Comparison) rule needs WriteValue: the value Enforce writes."
        return $result
    }

    try {
        $keys = @(Resolve-ThemisRegistryKey -Path $Rule.Path)
        if ($keys.Count -eq 0) {
            $result.Status = 'NotApplicable'
            $result.IsCompliant = $true
            $result.Reason = "No key matches $($Rule.Path)."
            $result.Data = @{ Keys = @() }
            return $result
        }
        $wildcard = $Rule.Path -match '\*'
        $states = @($keys | ForEach-Object { Get-ThemisRegistryState -Path $_ -ValueName $Rule.ValueName })
        $readable = @($states | Where-Object { $_.Readable })
        $checks = @{}
        foreach ($s in $readable) { $checks[$s.Path] = Test-ThemisRegistryState -Rule $Rule -State $s }
        $failing = @($readable | Where-Object { -not $checks[$_.Path].Match })
        $result.Data = @{ Keys = $states }

        if ($readable.Count -lt $states.Count -and $failing.Count -eq 0) {
            # Some keys cannot be read and none of the readable ones fails: the result is unknown.
            $result.Status = if (Test-ThemisElevated) { 'Error' } else { 'NeedsElevation' }
            $result.Reason = "Cannot read $(@($states | Where-Object { -not $_.Readable } | ForEach-Object Path) -join ', ')."
            return $result
        }

        # What the report shows: the value of a single key, or how many keys comply.
        if (-not $wildcard) {
            $single = $states[0]
            $result.Actual = if ($single.Exists) { $single.Value } elseif ($checks[$single.Path].ByDefault) { "(default) $($Rule.Default)" } else { $null }
        }
        else { $result.Actual = "$($readable.Count - $failing.Count) of $($states.Count) keys comply" }

        if ($failing.Count -eq 0) {
            $result.Status = "Compliant"
            $result.IsCompliant = $true
            $first = $checks[$readable[0].Path]
            $result.Reason = if ($Rule.Ensure -eq 'Absent') { "Value '$($Rule.ValueName)' is not set." }
            elseif ($first.ByDefault) { "Not set; the Windows default ($($Rule.Default)) meets the rule." }
            elseif ($wildcard) { "Every matching key complies (required: $($first.Expected))." }
            else { "Value is $($readable[0].Value) (required: $($first.Expected))." }
            return $result
        }

        # Not compliant. A single key keeps the historical statuses for a missing key or value.
        $first = $failing[0]
        if ($Rule.Ensure -eq 'Absent') {
            $result.Status = 'Non-Compliant'
            $result.Reason = "Value '$($Rule.ValueName)' should not exist but is $($first.Value)."
        }
        elseif (-not $wildcard -and -not $first.KeyExists) {
            $result.Status = 'MissingKey'
            $result.Reason = "Key path not found: $($Rule.Path)"
        }
        elseif (-not $wildcard -and -not $first.Exists) {
            $result.Status = 'MissingValue'
            $result.Reason = "Value '$($Rule.ValueName)' not found."
        }
        else {
            $result.Status = 'Non-Compliant'
            $where = if ($wildcard) { " in $($first.Path)" } else { '' }
            $result.Reason = "Expected $($checks[$first.Path].Expected) but found '$($first.Value)'$where."
        }
        if ($Mode -ne 'Enforce') { return $result }

        # ENFORCEMENT: every key that fails is changed. What to restore is recorded as soon as each key
        # changes, so a failure halfway still returns how to undo the keys already changed.
        $previous = [System.Collections.Generic.List[object]]::new()
        $result.Previous = $previous
        $kind = if ($Rule.Type) { "$($Rule.Type)" } else { 'String' }
        $target = if ($null -ne $Rule.WriteValue) { $Rule.WriteValue } else { $Rule.Value }
        try {
            foreach ($s in $failing) {
                $undo = if ($s.Exists) { [ordered]@{ Path = $s.Path; ValueName = $Rule.ValueName; Value = $s.Value; Type = $s.Kind } }
                else { [ordered]@{ Path = $s.Path; ValueName = $Rule.ValueName; Ensure = 'Absent'; RemoveKeyIfEmpty = -not $s.KeyExists } }
                # A key created for the value is a change even if writing the value then fails.
                if (-not $s.KeyExists -and $Rule.Ensure -ne 'Absent') { New-Item -Path $s.Path -Force -ErrorAction Stop | Out-Null; $previous.Add($undo); $undo = $null }

                if ($Rule.Ensure -eq 'Absent') {
                    Remove-ItemProperty -LiteralPath $s.Path -Name $Rule.ValueName -Force -ErrorAction Stop
                    if ($Rule.RemoveKeyIfEmpty) {
                        $item = Get-Item -LiteralPath $s.Path -ErrorAction SilentlyContinue
                        if ($item -and $item.ValueCount -eq 0 -and $item.SubKeyCount -eq 0) { Remove-Item -LiteralPath $s.Path -Force -ErrorAction Stop }
                    }
                }
                else {
                    New-ItemProperty -LiteralPath $s.Path -Name $Rule.ValueName -Value (ConvertTo-ThemisRegistryData -Value $target -Kind $kind) -PropertyType $kind -Force -ErrorAction Stop | Out-Null
                }
                if ($undo) { $previous.Add($undo) }
            }
        }
        catch {
            $result.Status = "EnforceFailed"
            $result.Reason = "Failed to set value: $_"
            return $result
        }

        # Read back instead of assuming the change worked (Group Policy can put values back).
        $after = @($keys | ForEach-Object { Get-ThemisRegistryState -Path $_ -ValueName $Rule.ValueName })
        $result.Data = @{ Keys = $after }
        $stillFailing = @($after | Where-Object { -not $_.Readable -or -not (Test-ThemisRegistryState -Rule $Rule -State $_).Match })
        if ($stillFailing.Count) {
            $result.Status = 'EnforceFailed'
            $result.Reason = "The value was written but reads back as '$($stillFailing[0].Value)' in $($stillFailing[0].Path)."
            return $result
        }
        $result.Status = "Fixed"
        $result.IsCompliant = $true
        $result.Reason = if ($Rule.Ensure -eq 'Absent') { "Value '$($Rule.ValueName)' removed." } else { "Value set to $target." }
        $result.Actual = if ($wildcard) { "$($after.Count) of $($after.Count) keys comply" } elseif ($after[0].Exists) { $after[0].Value } else { $null }
    }
    catch {
        $result.Status = "Error"
        $result.Reason = "Provider Error: $_"
    }

    return $result
}
