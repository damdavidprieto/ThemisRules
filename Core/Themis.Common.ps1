# ThemisRules shared helpers (private).
#
# Value comparison used by every provider, elevation check, the per-run cache, and thin
# wrappers around auditpol, secedit and the firewall cmdlets. The wrappers are separate
# functions so the tests can mock them without touching the machine.

# Cache for data that is expensive to read (the whole audit policy, the security policy).
# Invoke-ThemisPolicy clears it at the start of every run.
$script:ThemisRunCache = @{}

function Test-ThemisElevated {
    <#
    .SYNOPSIS
        True when the session runs as administrator (always $false off Windows).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) { return $false }
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ThemisValue {
    <#
    .SYNOPSIS
        Compares an actual value with the rule: Equal (default), AtLeast, AtMost or Between.
    .DESCRIPTION
        Returns @{ Match = <bool>; Expected = <text for the report> }. Numeric comparisons
        need both values to be numbers; Between uses the rule's Min and Max. Text values are
        compared without case.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [AllowNull()] $Actual,
        [Parameter(Mandatory = $true)] [object]$Rule
    )

    $comparison = if ($Rule.Comparison) { [string]$Rule.Comparison } else { 'Equal' }
    $number = 0.0
    $actualIsNumber = $null -ne $Actual -and [double]::TryParse([string]$Actual, [ref]$number)
    $actualNumber = $number

    switch ($comparison) {
        'Equal' {
            if ($actualIsNumber -and [double]::TryParse([string]$Rule.Value, [ref]$number)) {
                return @{ Match = ($actualNumber -eq $number); Expected = "$($Rule.Value)" }
            }
            return @{ Match = ("$Actual" -eq "$($Rule.Value)"); Expected = "$($Rule.Value)" }
        }
        'AtLeast' {
            $ok = $actualIsNumber -and [double]::TryParse([string]$Rule.Value, [ref]$number) -and $actualNumber -ge $number
            return @{ Match = [bool]$ok; Expected = "$($Rule.Value) or more" }
        }
        'AtMost' {
            $ok = $actualIsNumber -and [double]::TryParse([string]$Rule.Value, [ref]$number) -and $actualNumber -le $number
            return @{ Match = [bool]$ok; Expected = "$($Rule.Value) or less" }
        }
        'Between' {
            $min = 0.0; $max = 0.0
            $ok = $actualIsNumber -and [double]::TryParse([string]$Rule.Min, [ref]$min) -and [double]::TryParse([string]$Rule.Max, [ref]$max) -and
                $actualNumber -ge $min -and $actualNumber -le $max
            return @{ Match = [bool]$ok; Expected = "between $($Rule.Min) and $($Rule.Max)" }
        }
        default { throw "Unknown Comparison '$comparison'. Use Equal, AtLeast, AtMost or Between." }
    }
}

# --- Audit policy (auditpol) ---

function Get-ThemisAuditPolicySetting {
    <#
    .SYNOPSIS
        Returns the effective audit policy as @{ '{GUID}' = 0..3 } (0 none, 1 success, 2 failure, 3 both).
    .DESCRIPTION
        Uses auditpol /backup, whose numeric "Setting Value" column does not depend on the
        Windows display language, unlike the text of auditpol /get. Needs elevation.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Returns the set of subcategory settings; private.')]
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    if ($script:ThemisRunCache.ContainsKey('AuditPolicy')) { return $script:ThemisRunCache['AuditPolicy'] }

    $file = Join-Path ([IO.Path]::GetTempPath()) ("themis_audit_{0}.csv" -f [guid]::NewGuid().ToString('N'))
    try {
        $null = & auditpol.exe /backup "/file:$file"
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $file)) { throw "auditpol /backup failed with exit code $LASTEXITCODE." }

        $settings = @{}
        foreach ($line in Get-Content -LiteralPath $file | Select-Object -Skip 1) {
            # Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
            $fields = $line -split ','
            if ($fields.Count -ge 7 -and $fields[3] -match '^\{[0-9A-Fa-f-]{36}\}$') {
                $settings[$fields[3].ToUpperInvariant()] = [int]$fields[6]
            }
        }
        $script:ThemisRunCache['AuditPolicy'] = $settings
        return $settings
    }
    finally {
        Remove-Item -LiteralPath $file -ErrorAction SilentlyContinue
    }
}

function Set-ThemisAuditPolicySetting {
    <#
    .SYNOPSIS
        Enables or disables success and failure auditing for one subcategory (by GUID).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][ValidatePattern('^\{[0-9A-Fa-f-]{36}\}$')][string]$Subcategory,
        [Parameter(Mandatory = $true)][bool]$Success,
        [Parameter(Mandatory = $true)][bool]$Failure
    )

    if (-not $PSCmdlet.ShouldProcess($Subcategory, 'Set audit policy')) { return }
    $successFlag = if ($Success) { 'enable' } else { 'disable' }
    $failureFlag = if ($Failure) { 'enable' } else { 'disable' }
    $null = & auditpol.exe /set "/subcategory:$Subcategory" "/success:$successFlag" "/failure:$failureFlag"
    if ($LASTEXITCODE -ne 0) { throw "auditpol /set failed with exit code $LASTEXITCODE." }
    $script:ThemisRunCache.Remove('AuditPolicy')
}

# --- Security policy (secedit, [System Access]) ---

function Get-ThemisSecurityPolicy {
    <#
    .SYNOPSIS
        Returns the [System Access] section of the local security policy as a hashtable.
    .DESCRIPTION
        Uses secedit /export. Needs elevation.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    if ($script:ThemisRunCache.ContainsKey('SecurityPolicy')) { return $script:ThemisRunCache['SecurityPolicy'] }

    $file = Join-Path ([IO.Path]::GetTempPath()) ("themis_secpol_{0}.inf" -f [guid]::NewGuid().ToString('N'))
    try {
        $null = & secedit.exe /export /cfg $file /areas SECURITYPOLICY /quiet
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $file)) { throw "secedit /export failed with exit code $LASTEXITCODE." }

        $settings = @{}
        $inSection = $false
        foreach ($line in Get-Content -LiteralPath $file) {
            if ($line -match '^\s*\[(.+)\]\s*$') { $inSection = ($matches[1] -eq 'System Access'); continue }
            if ($inSection -and $line -match '^\s*([A-Za-z]+)\s*=\s*(.*?)\s*$') { $settings[$matches[1]] = $matches[2].Trim('"') }
        }
        $script:ThemisRunCache['SecurityPolicy'] = $settings
        return $settings
    }
    finally {
        Remove-Item -LiteralPath $file -ErrorAction SilentlyContinue
    }
}

function Set-ThemisSecurityPolicy {
    <#
    .SYNOPSIS
        Applies [System Access] values to the local security policy with secedit /configure.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Settings
    )

    if (-not $PSCmdlet.ShouldProcess(($Settings.Keys -join ', '), 'Set local security policy')) { return }

    $id = [guid]::NewGuid().ToString('N')
    $inf = Join-Path ([IO.Path]::GetTempPath()) "themis_secpol_$id.inf"
    $db = Join-Path ([IO.Path]::GetTempPath()) "themis_secpol_$id.sdb"
    $lines = @('[Unicode]', 'Unicode=yes', '[System Access]')
    $lines += foreach ($key in $Settings.Keys) { "$key = $($Settings[$key])" }
    $lines += @('[Version]', 'signature="$CHICAGO$"', 'Revision=1')
    try {
        Set-Content -LiteralPath $inf -Value $lines -Encoding Unicode
        $null = & secedit.exe /configure /db $db /cfg $inf /areas SECURITYPOLICY /quiet
        if ($LASTEXITCODE -ne 0) { throw "secedit /configure failed with exit code $LASTEXITCODE." }
    }
    finally {
        Remove-Item -LiteralPath $inf, $db -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ($db -replace '\.sdb$', '.jfm') -ErrorAction SilentlyContinue
        $script:ThemisRunCache.Remove('SecurityPolicy')
    }
}

# --- Windows Firewall profiles ---

function Get-ThemisFirewallProfile {
    <#
    .SYNOPSIS
        Returns the effective settings of a firewall profile (local settings merged with Group Policy).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', '', Justification = 'NetSecurity is a Windows module; the provider reports an error where it is missing.')]
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Mandatory = $true)][ValidateSet('Domain', 'Private', 'Public')][string]$Name)

    return (Get-NetFirewallProfile -Name $Name -PolicyStore ActiveStore -ErrorAction Stop)
}

function Set-ThemisFirewallProfile {
    <#
    .SYNOPSIS
        Changes one setting of a firewall profile in the local (persistent) store.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', '', Justification = 'NetSecurity is a Windows module; the provider reports an error where it is missing.')]
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Domain', 'Private', 'Public')][string]$Name,
        [Parameter(Mandatory = $true)][string]$Setting,
        [Parameter(Mandatory = $true)]$Value
    )

    if (-not $PSCmdlet.ShouldProcess("$Name profile", "Set $Setting to $Value")) { return }
    $parameters = @{ Name = $Name; ErrorAction = 'Stop'; $Setting = $Value }
    Set-NetFirewallProfile @parameters
}
