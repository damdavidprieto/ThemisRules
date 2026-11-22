# ThemisRules EventLog provider: maximum size of an event log.
#
#   LogName    Log name, for example Security or Microsoft-Windows-PowerShell/Operational.
#   MaxSizeMB  Required maximum size in MB. A larger size is compliant, unless Exact is set.
#   Exact      Require exactly MaxSizeMB (used by restore rules, to put the old size back).
# A log that this Windows does not have is NotApplicable. Reading works without elevation for most logs;
# changing the size needs an elevated session. Logs that are too small overwrite their oldest events: the
# trace of an attack can be gone before anyone looks.

function Get-ThemisEventLogSize {
    <#
    .SYNOPSIS
        The maximum size of a log in bytes, or $null when the log does not exist. Separate so the tests can mock it.
    #>
    [CmdletBinding()]
    [OutputType([long])]
    param([Parameter(Mandatory = $true)][string]$LogName)

    try {
        $config = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($LogName)
        try { return [long]$config.MaximumSizeInBytes } finally { $config.Dispose() }
    }
    catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] { return $null }
}

function Set-ThemisEventLogSize {
    <#
    .SYNOPSIS
        Sets the maximum size of a log, in bytes.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$LogName, [Parameter(Mandatory = $true)][long]$Bytes)

    if (-not $PSCmdlet.ShouldProcess($LogName, "Set maximum size to $([math]::Round($Bytes / 1MB)) MB")) { return }
    $config = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($LogName)
    try {
        $config.MaximumSizeInBytes = $Bytes
        $config.SaveChanges()
    }
    finally { $config.Dispose() }
}

function Invoke-ThemisEventLogRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null }

    $name = "$($Rule.LogName)"
    if ($name -notmatch '^[A-Za-z0-9 ._/-]+$') {
        $result.Status = 'Error'
        $result.Reason = "LogName must be an event log name such as Security or Microsoft-Windows-PowerShell/Operational: '$name'."
        return $result
    }
    $mb = 0
    if (-not [int]::TryParse("$($Rule.MaxSizeMB)", [ref]$mb) -or $mb -lt 1 -or $mb -gt 16384) {
        $result.Status = 'Error'
        $result.Reason = "MaxSizeMB must be a whole number of megabytes between 1 and 16384: '$($Rule.MaxSizeMB)'."
        return $result
    }
    $wanted = [long]$mb * 1MB

    try {
        $current = Get-ThemisEventLogSize -LogName $name
        if ($null -eq $current) {
            $result.Status = 'NotApplicable'
            $result.IsCompliant = $true
            $result.Reason = "This Windows has no log $name."
            $result.Data = @{ Missing = $true }
            return $result
        }
        $currentMb = [math]::Round($current / 1MB)
        $result.Actual = $currentMb
        $result.Data = @{ Missing = $false; Value = $currentMb }
        $compliant = if ($Rule.Exact) { $current -eq $wanted } else { $current -ge $wanted }
        if ($compliant) {
            $result.Status = 'Compliant'
            $result.IsCompliant = $true
            $result.Reason = "$name keeps up to $currentMb MB."
            return $result
        }

        $result.Status = 'Non-Compliant'
        $result.Reason = "$name keeps up to $currentMb MB; required: $(if ($Rule.Exact) { 'exactly' } else { 'at least' }) $mb MB."
        if ($Mode -ne 'Enforce') { return $result }
        if (-not (Test-ThemisElevated)) {
            $result.Status = 'NeedsElevation'
            $result.Reason = 'Changing the size of an event log requires an elevated session (Run as administrator).'
            return $result
        }

        $null = Set-ThemisEventLogSize -LogName $name -Bytes $wanted -Confirm:$false
        $after = Get-ThemisEventLogSize -LogName $name
        $result.Actual = [math]::Round($after / 1MB)
        $result.Data = @{ Missing = $false; Value = [math]::Round($after / 1MB) }
        if ($after -eq $wanted) {
            $result.Previous = [ordered]@{ LogName = $name; MaxSizeMB = [int][math]::Max(1, [math]::Round($current / 1MB)); Exact = $true }
            $result.Status = 'Fixed'
            $result.IsCompliant = $true
            $result.Reason = "$name now keeps up to $mb MB."
        }
        else {
            $result.Status = 'EnforceFailed'
            $result.Reason = "$name still keeps up to $([math]::Round($after / 1MB)) MB."
        }
    }
    catch {
        $result.Status = 'Error'
        $result.Reason = "Provider Error: $_"
    }
    return $result
}
