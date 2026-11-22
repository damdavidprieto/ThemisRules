# ThemisRules Feature provider: Windows optional features (Get-WindowsOptionalFeature).
#
#   Feature   Feature name, for example SMB1Protocol or MicrosoftWindowsPowerShellV2Root.
#   State     Disabled or Enabled.
# A feature that this Windows version does not include is NotApplicable. Reading features needs an
# elevated session. Changes usually take effect after a restart.

function Get-ThemisOptionalFeature {
    <#
    .SYNOPSIS
        The state of an optional feature (Enabled, Disabled, DisabledWithPayloadRemoved...), or $null
        when this Windows does not include it. Separate so the tests can mock it.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', '', Justification = 'DISM is a Windows module; the provider reports an error where it is missing.')]
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Name)

    $feature = Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction SilentlyContinue
    if (-not $feature) { return $null }
    return "$($feature.State)"
}

function Set-ThemisOptionalFeature {
    <#
    .SYNOPSIS
        Enables or disables an optional feature without restarting.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', '', Justification = 'DISM is a Windows module; the provider reports an error where it is missing.')]
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][ValidateSet('Enabled', 'Disabled')][string]$State)

    if (-not $PSCmdlet.ShouldProcess($Name, "Set optional feature to $State")) { return }
    if ($State -eq 'Disabled') { Disable-WindowsOptionalFeature -Online -FeatureName $Name -NoRestart -ErrorAction Stop | Out-Null }
    else { Enable-WindowsOptionalFeature -Online -FeatureName $Name -NoRestart -ErrorAction Stop | Out-Null }
}

function Invoke-ThemisFeatureRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null }

    $name = "$($Rule.Feature)"
    if ($name -notmatch '^[A-Za-z0-9._-]+$') {
        $result.Status = 'Error'
        $result.Reason = "Feature must be an optional feature name such as SMB1Protocol: '$name'."
        return $result
    }
    if ("$($Rule.State)" -notin 'Enabled', 'Disabled') {
        $result.Status = 'Error'
        $result.Reason = "State must be Enabled or Disabled: '$($Rule.State)'."
        return $result
    }
    if (-not (Get-Command -Name 'Get-WindowsOptionalFeature' -ErrorAction SilentlyContinue)) {
        $result.Status = 'Error'
        $result.Reason = 'The DISM module (Get-WindowsOptionalFeature) is not available on this system.'
        return $result
    }
    if (-not (Test-ThemisElevated)) {
        $result.Status = 'NeedsElevation'
        $result.Reason = 'Reading optional features requires an elevated session (Run as administrator).'
        return $result
    }

    try {
        $current = Get-ThemisOptionalFeature -Name $name
        if ($null -eq $current) {
            $result.Status = 'NotApplicable'
            $result.IsCompliant = $true
            $result.Reason = "This Windows does not include the feature $name."
            $result.Data = @{ Missing = $true }
            return $result
        }
        $result.Actual = $current
        $result.Data = @{ Missing = $false; State = $current }
        $isDisabled = $current -in 'Disabled', 'DisabledWithPayloadRemoved'
        $compliant = if ($Rule.State -eq 'Disabled') { $isDisabled } else { $current -eq 'Enabled' }
        if ($compliant) {
            $result.Status = 'Compliant'
            $result.IsCompliant = $true
            $result.Reason = "$name is $current."
            return $result
        }

        $result.Status = 'Non-Compliant'
        $result.Reason = "$name is $current; required: $($Rule.State)."
        if ($Mode -ne 'Enforce') { return $result }

        $result.Previous = [ordered]@{ Feature = $name; State = $(if ($isDisabled) { 'Disabled' } else { 'Enabled' }) }
        Set-ThemisOptionalFeature -Name $name -State $Rule.State -Confirm:$false
        $after = Get-ThemisOptionalFeature -Name $name
        $result.Actual = $after
        $result.Data = @{ Missing = $false; State = $after }
        $ok = if ($Rule.State -eq 'Disabled') { $after -in 'Disabled', 'DisabledWithPayloadRemoved', 'DisablePending' } else { $after -in 'Enabled', 'EnablePending' }
        if ($ok) {
            $result.Status = 'Fixed'
            $result.IsCompliant = $true
            $result.Reason = "$name set to $($Rule.State) (it may need a restart)."
        }
        else {
            $result.Status = 'EnforceFailed'
            $result.Reason = "$name is still $after."
        }
    }
    catch {
        $result.Status = $(if ($result.Contains('Previous')) { 'EnforceFailed' } else { 'Error' })
        $result.Reason = "Provider Error: $_"
    }
    return $result
}
