# ThemisRules DefenderPreference provider: a Microsoft Defender Antivirus setting, or one attack surface reduction
# rule, read and changed with Get-MpPreference and Set-MpPreference.
#
#   Setting    A setting from the list below, such as PUAProtection or EnableNetworkProtection.
#   Value      The value it must have (a number, or true/false); Comparison works as in other rules.
# or
#   AsrRule    The GUID of an attack surface reduction rule.
#   AsrAction  Block (default), Audit, Warn, Disabled, or Absent (restore rules: the rule was not configured).
#
# Unlike the policy keys in the registry, these are the settings Defender really uses: a change that Tamper
# Protection or a Group Policy undoes is EnforceFailed instead of looking applied. When Defender is not the active
# antivirus (another one is), the rule is NotApplicable. Changing settings needs an elevated session.

# Settings that can be read and changed, and the values each one takes.
$script:ThemisDefenderSettings = @{
    DisableRealtimeMonitoring      = 'Bool'
    DisableBehaviorMonitoring      = 'Bool'
    DisableIOAVProtection          = 'Bool'
    DisableScriptScanning          = 'Bool'
    DisableRemovableDriveScanning  = 'Bool'
    DisableEmailScanning           = 'Bool'
    DisableArchiveScanning         = 'Bool'
    DisableBlockAtFirstSeen        = 'Bool'
    PUAProtection                  = '0-2'
    MAPSReporting                  = '0-2'
    SubmitSamplesConsent           = '0-3'
    EnableNetworkProtection        = '0-2'
    EnableControlledFolderAccess   = '0-6'
    CloudBlockLevel                = '0-6'
    CloudExtendedTimeout           = '0-50'
    SignatureUpdateInterval        = '0-24'
}
$script:ThemisAsrActions = @{ Disabled = 0; Block = 1; Audit = 2; Warn = 6 }

function Get-ThemisMpPreference {
    <#
    .SYNOPSIS
        Get-MpPreference, or $null when Defender is not available. Separate so the tests can mock it.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', '', Justification = 'Only called when the Defender module exists.')]
    [CmdletBinding()]
    param()
    if (-not (Get-Command -Name 'Get-MpPreference' -ErrorAction SilentlyContinue)) { return $null }
    return Get-MpPreference -ErrorAction Stop
}

function Set-ThemisMpPreference {
    <#
    .SYNOPSIS
        Changes one Defender setting, or one attack surface reduction rule (Action $null removes it).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', '', Justification = 'Only called when the Defender module exists.')]
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Setting, $Value, [string]$AsrRule, $AsrAction)
    if ($AsrRule) {
        if (-not $PSCmdlet.ShouldProcess($AsrRule, 'Set attack surface reduction rule')) { return }
        if ($null -eq $AsrAction) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $AsrRule -ErrorAction Stop }
        else { Add-MpPreference -AttackSurfaceReductionRules_Ids $AsrRule -AttackSurfaceReductionRules_Actions ([int]$AsrAction) -ErrorAction Stop }
        return
    }
    if (-not $PSCmdlet.ShouldProcess($Setting, "Set Defender setting to $Value")) { return }
    $arguments = @{ $Setting = $Value; ErrorAction = 'Stop' }
    Set-MpPreference @arguments
}

function Get-ThemisAsrAction {
    <#
    .SYNOPSIS
        The action (0, 1, 2 or 6) of an attack surface reduction rule in a preference object, or $null when it is not configured.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param($Preference, [Parameter(Mandatory = $true)][string]$Id)
    $ids = @($Preference.AttackSurfaceReductionRules_Ids)
    $actions = @($Preference.AttackSurfaceReductionRules_Actions)
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if ([string]::Equals("$($ids[$i])", $Id, 'OrdinalIgnoreCase')) { return [int]$actions[$i] }
    }
    return $null
}

function Invoke-ThemisDefenderPreferenceRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null }
    $asr = "$($Rule.AsrRule)"
    $setting = "$($Rule.Setting)"
    $problem = $null
    $wanted = $null
    if ($asr) {
        if ($asr -notmatch '^[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$') { $problem = "AsrRule must be the GUID of an attack surface reduction rule: '$asr'." }
        else {
            $actionName = if ($Rule.AsrAction) { "$($Rule.AsrAction)" } else { 'Block' }
            if ($actionName -eq 'Absent') { $wanted = $null }
            elseif ($script:ThemisAsrActions.ContainsKey($actionName)) { $wanted = $script:ThemisAsrActions[$actionName] }
            else { $problem = "AsrAction must be Block, Audit, Warn, Disabled or Absent: '$actionName'." }
        }
    }
    elseif (-not $script:ThemisDefenderSettings.ContainsKey($setting)) {
        $problem = "Setting must be one of $((@($script:ThemisDefenderSettings.Keys) | Sort-Object) -join ', '): '$setting'."
    }
    else {
        $kind = $script:ThemisDefenderSettings[$setting]
        if ($kind -eq 'Bool') {
            if ("$($Rule.Value)" -notin 'True', 'False', '1', '0') { $problem = "$setting takes true or false: '$($Rule.Value)'." }
            else { $wanted = "$($Rule.Value)" -in 'True', '1' }
        }
        else {
            $min, $max = $kind -split '-'
            $number = 0
            if (-not [int]::TryParse("$($Rule.Value)", [ref]$number) -or $number -lt [int]$min -or $number -gt [int]$max) { $problem = "$setting takes a whole number from $min to $max`: '$($Rule.Value)'." }
            else { $wanted = $number }
        }
    }
    if ($problem) { $result.Status = 'Error'; $result.Reason = $problem; return $result }

    try {
        # With another antivirus as the main one, Defender's settings do nothing.
        $defender = (Read-ThemisFactSource -Source 'Antivirus').DefenderActive
        if ($defender -eq $false) {
            $result.Status = 'NotApplicable'
            $result.IsCompliant = $true
            $result.Reason = 'Microsoft Defender is not the active antivirus on this machine.'
            return $result
        }
        $preference = Get-ThemisMpPreference
        if ($null -eq $preference) {
            $result.Status = 'NotApplicable'
            $result.IsCompliant = $true
            $result.Reason = 'Microsoft Defender Antivirus is not available on this machine.'
            return $result
        }

        if ($asr) {
            $current = Get-ThemisAsrAction -Preference $preference -Id $asr
            $name = @($script:ThemisAsrActions.Keys | Where-Object { $script:ThemisAsrActions[$_] -eq $current }) | Select-Object -First 1
            $result.Actual = if ($null -eq $current) { 'NotConfigured' } else { $name }
            $result.Data = @{ AsrRule = $asr; Action = $current }
            $compliant = $current -eq $wanted
            $label = "Attack surface reduction rule $asr"
            $want = if ($null -eq $wanted) { 'not configured' } else { "$($Rule.AsrAction)" }
            if (-not $want -or $want -eq '') { $want = 'Block' }
        }
        else {
            $current = $preference.$setting
            if ($script:ThemisDefenderSettings[$setting] -eq 'Bool') { $current = [bool]$current } elseif ($null -ne $current) { $current = [int]$current }
            $result.Actual = $current
            $result.Data = @{ Setting = $setting; Value = $current }
            $compliant = if ($script:ThemisDefenderSettings[$setting] -eq 'Bool') { $current -eq $wanted } else { (Test-ThemisValue -Actual $current -Rule ([pscustomobject]@{ Value = $wanted; Comparison = $Rule.Comparison; Min = $Rule.Min; Max = $Rule.Max })).Match }
            $label = "Defender setting $setting"
            $want = "$wanted"
        }
        if ($compliant) {
            $result.Status = 'Compliant'
            $result.IsCompliant = $true
            $result.Reason = "$label is $($result.Actual)."
            return $result
        }
        $result.Status = 'Non-Compliant'
        $result.Reason = "$label is $($result.Actual); required: $want."
        if ($Mode -ne 'Enforce') { return $result }
        if (-not (Test-ThemisElevated)) {
            $result.Status = 'NeedsElevation'
            $result.Reason = 'Changing Defender settings requires an elevated session (Run as administrator).'
            return $result
        }

        if ($asr) { Set-ThemisMpPreference -AsrRule $asr -AsrAction $wanted -Confirm:$false }
        else { Set-ThemisMpPreference -Setting $setting -Value $wanted -Confirm:$false }
        $after = Get-ThemisMpPreference
        $now = if ($asr) { Get-ThemisAsrAction -Preference $after -Id $asr } else { $after.$setting }
        if ($null -ne $now -and -not $asr) { $now = if ($script:ThemisDefenderSettings[$setting] -eq 'Bool') { [bool]$now } else { [int]$now } }
        if ($now -ne $wanted) {
            $result.Status = 'EnforceFailed'
            $result.Reason = "$label did not change: Tamper Protection or a Group Policy may keep it."
            return $result
        }
        $result.Previous = if ($asr) {
            $back = if ($null -eq $current) { 'Absent' } else { @($script:ThemisAsrActions.Keys | Where-Object { $script:ThemisAsrActions[$_] -eq $current }) | Select-Object -First 1 }
            [ordered]@{ AsrRule = $asr; AsrAction = $back }
        }
        else { [ordered]@{ Setting = $setting; Value = $current } }
        $result.Actual = if ($asr) { $want } else { $wanted }
        $result.Status = 'Fixed'
        $result.IsCompliant = $true
        $result.Reason = "$label is now $want."
    }
    catch {
        $result.Status = 'Error'
        $result.Reason = "Provider Error: $_"
    }
    return $result
}
