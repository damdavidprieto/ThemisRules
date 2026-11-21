# ThemisRules shared helpers (private).
#
# Value comparison used by every provider, elevation check, the per-run cache, and thin
# wrappers around auditpol, secedit and the firewall cmdlets. The wrappers are separate
# functions so the tests can mock them without touching the machine.

# Cache for data that is expensive to read (the whole audit policy, the security policy).
# Invoke-ThemisPolicy clears it at the start of every run.
$script:ThemisRunCache = @{}

function Get-ThemisSystemTool {
    <#
    .SYNOPSIS
        Full path of a Windows tool in System32 (auditpol.exe, secedit.exe, sc.exe).
    .DESCRIPTION
        Tools are never called by bare name: PowerShell would search the current folder and the
        PATH first, and in an elevated session a program planted there with the same name would
        run as administrator.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_-]+\.exe$')][string]$Name)

    return (Join-Path ([Environment]::GetFolderPath('System')) $Name)
}

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
        $null = & (Get-ThemisSystemTool 'auditpol.exe') /backup "/file:$file"
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
    $null = & (Get-ThemisSystemTool 'auditpol.exe') /set "/subcategory:$Subcategory" "/success:$successFlag" "/failure:$failureFlag"
    if ($LASTEXITCODE -ne 0) { throw "auditpol /set failed with exit code $LASTEXITCODE." }
    $script:ThemisRunCache.Remove('AuditPolicy')
}

# --- Local security policy and user rights (secedit) ---

function Read-ThemisSecurityTemplate {
    <#
    .SYNOPSIS
        Exports the local security policy once per run and returns its [System Access] and
        [Privilege Rights] sections. Needs elevation.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    if ($script:ThemisRunCache.ContainsKey('SecurityTemplate')) { return $script:ThemisRunCache['SecurityTemplate'] }

    $file = Join-Path ([IO.Path]::GetTempPath()) ("themis_secpol_{0}.inf" -f [guid]::NewGuid().ToString('N'))
    try {
        $null = & (Get-ThemisSystemTool 'secedit.exe') /export /cfg $file /areas SECURITYPOLICY USER_RIGHTS /quiet
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $file)) { throw "secedit /export failed with exit code $LASTEXITCODE." }

        $template = @{ 'System Access' = @{}; 'Privilege Rights' = @{} }
        $section = $null
        foreach ($line in Get-Content -LiteralPath $file) {
            if ($line -match '^\s*\[(.+)\]\s*$') { $section = $matches[1]; continue }
            if ($template.ContainsKey("$section") -and $line -match '^\s*([A-Za-z]+)\s*=\s*(.*?)\s*$') {
                $template[$section][$matches[1]] = $matches[2].Trim('"')
            }
        }
        $script:ThemisRunCache['SecurityTemplate'] = $template
        return $template
    }
    finally {
        Remove-Item -LiteralPath $file -ErrorAction SilentlyContinue
    }
}

function Invoke-ThemisSecurityTemplate {
    <#
    .SYNOPSIS
        Applies lines of one section of a security template with secedit /configure.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('System Access', 'Privilege Rights')][string]$Section,
        [Parameter(Mandatory = $true)][string[]]$Lines
    )

    if (-not $PSCmdlet.ShouldProcess($Section, 'Set local security policy')) { return }

    $area = if ($Section -eq 'System Access') { 'SECURITYPOLICY' } else { 'USER_RIGHTS' }
    $id = [guid]::NewGuid().ToString('N')
    $inf = Join-Path ([IO.Path]::GetTempPath()) "themis_secpol_$id.inf"
    $db = Join-Path ([IO.Path]::GetTempPath()) "themis_secpol_$id.sdb"
    $content = @('[Unicode]', 'Unicode=yes', "[$Section]") + $Lines + @('[Version]', 'signature="$CHICAGO$"', 'Revision=1')
    try {
        Set-Content -LiteralPath $inf -Value $content -Encoding Unicode
        $null = & (Get-ThemisSystemTool 'secedit.exe') /configure /db $db /cfg $inf /areas $area /quiet
        if ($LASTEXITCODE -ne 0) { throw "secedit /configure failed with exit code $LASTEXITCODE." }
    }
    finally {
        Remove-Item -LiteralPath $inf, $db -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ($db -replace '\.sdb$', '.jfm') -ErrorAction SilentlyContinue
        $script:ThemisRunCache.Remove('SecurityTemplate')
    }
}

function Get-ThemisSecurityPolicy {
    <#
    .SYNOPSIS
        Returns the [System Access] section of the local security policy as a hashtable.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return (Read-ThemisSecurityTemplate)['System Access']
}

function Set-ThemisSecurityPolicy {
    <#
    .SYNOPSIS
        Applies [System Access] values (whole numbers, checked by the provider) to the local security policy.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Settings
    )

    if (-not $PSCmdlet.ShouldProcess(($Settings.Keys -join ', '), 'Set local security policy')) { return }
    $lines = foreach ($key in $Settings.Keys) { "$key = $([int]$Settings[$key])" }
    Invoke-ThemisSecurityTemplate -Section 'System Access' -Lines $lines -Confirm:$false
}

function ConvertTo-ThemisSid {
    <#
    .SYNOPSIS
        Turns a secedit principal ("*S-1-5-32-544" or an account name) into a SID string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Principal)

    $value = $Principal.Trim()
    if ($value.StartsWith('*')) { return $value.Substring(1).ToUpperInvariant() }
    if ($value -match '^S-1-[0-9-]+$') { return $value.ToUpperInvariant() }
    try {
        return ([System.Security.Principal.NTAccount]$value).Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        return $value
    }
}

function Get-ThemisUserRight {
    <#
    .SYNOPSIS
        Returns the user rights assignments as @{ 'SeDebugPrivilege' = @('S-1-5-32-544', ...) }.
    .DESCRIPTION
        Principals are returned as SIDs, so the result does not depend on the Windows language.
        Rights that nobody holds are absent from the result. Needs elevation.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $rights = @{}
    $section = (Read-ThemisSecurityTemplate)['Privilege Rights']
    foreach ($right in $section.Keys) {
        $rights[$right] = @("$($section[$right])" -split ',' | Where-Object { $_.Trim() } | ForEach-Object { ConvertTo-ThemisSid -Principal $_ } | Sort-Object -Unique)
    }
    return $rights
}

function Set-ThemisUserRight {
    <#
    .SYNOPSIS
        Assigns a user right to exactly the given SIDs (none removes it from everyone).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][ValidatePattern('^Se[A-Za-z]+(Privilege|Right)$')][string]$Right,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Principals
    )

    foreach ($sid in $Principals) {
        if ($sid -notmatch '^S-1-[0-9]+(-[0-9]+)+$') { throw "Not a SID: '$sid'." }
    }
    if (-not $PSCmdlet.ShouldProcess($Right, "Assign to $(if ($Principals) { $Principals -join ', ' } else { 'nobody' })")) { return }
    $value = ($Principals | ForEach-Object { "*$_" }) -join ','
    Invoke-ThemisSecurityTemplate -Section 'Privilege Rights' -Lines @("$Right = $value") -Confirm:$false
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
