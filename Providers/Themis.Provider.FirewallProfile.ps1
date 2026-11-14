# ThemisRules FirewallProfile provider: settings of the Domain, Private and Public Windows
# Firewall profiles.
#
# Audit reads the effective settings (local settings merged with Group Policy). Enforce changes
# the local setting and reads it back: if a Group Policy defines the value, the change has no
# effect and the rule is reported as EnforceFailed.

$script:ThemisFirewallSettings = @{
    Enabled               = 'True', 'False'
    DefaultInboundAction  = 'Block', 'Allow'
    DefaultOutboundAction = 'Block', 'Allow'
    NotifyOnListen        = 'True', 'False'
    LogBlocked            = 'True', 'False'
    LogAllowed            = 'True', 'False'
    LogMaxSizeKilobytes   = $null
}

function Invoke-ThemisFirewallProfileRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null }

    $profileName = "$($Rule.Profile)"
    $setting = "$($Rule.Setting)"
    if ($profileName -notin 'Domain', 'Private', 'Public') {
        $result.Status = 'Error'
        $result.Reason = "Profile must be Domain, Private or Public: '$profileName'."
        return $result
    }
    if (-not $script:ThemisFirewallSettings.ContainsKey($setting)) {
        $result.Status = 'Error'
        $result.Reason = "Setting '$setting' is not supported. Supported settings: $($script:ThemisFirewallSettings.Keys -join ', ')."
        return $result
    }
    $allowed = $script:ThemisFirewallSettings[$setting]
    $number = 0
    if ($allowed -and "$($Rule.Value)" -notin $allowed) {
        $result.Status = 'Error'
        $result.Reason = "Value for $setting must be $($allowed -join ' or '): '$($Rule.Value)'."
        return $result
    }
    if (-not $allowed -and -not [int]::TryParse("$($Rule.Value)", [ref]$number)) {
        $result.Status = 'Error'
        $result.Reason = "Value for $setting must be a whole number: '$($Rule.Value)'."
        return $result
    }
    if (-not (Get-Command -Name 'Get-NetFirewallProfile' -ErrorAction SilentlyContinue)) {
        $result.Status = 'Error'
        $result.Reason = 'The NetSecurity module (Windows Firewall cmdlets) is not available on this system.'
        return $result
    }

    try {
        $current = "$((Get-ThemisFirewallProfile -Name $profileName).$setting)"
        $result.Actual = $current
        $check = Test-ThemisValue -Actual $current -Rule $Rule

        if ($check.Match) {
            $result.Status = 'Compliant'
            $result.IsCompliant = $true
            $result.Reason = "$profileName profile: $setting is $current."
            return $result
        }

        $result.Status = 'Non-Compliant'
        $result.Reason = "$profileName profile: $setting is $current; required: $($check.Expected)."

        if ($Mode -eq 'Enforce') {
            $newValue = if ($allowed) { "$($Rule.Value)" } else { [int]$Rule.Value }
            Set-ThemisFirewallProfile -Name $profileName -Setting $setting -Value $newValue -Confirm:$false
            $after = "$((Get-ThemisFirewallProfile -Name $profileName).$setting)"
            if ((Test-ThemisValue -Actual $after -Rule $Rule).Match) {
                $result.Status = 'Fixed'
                $result.IsCompliant = $true
                $result.Reason = "$profileName profile: $setting set to $newValue."
                $result.Actual = $after
            }
            else {
                $result.Status = 'EnforceFailed'
                $result.Reason = "$profileName profile: $setting is still $after; a Group Policy may override it."
            }
        }
    }
    catch {
        $result.Status = 'Error'
        $result.Reason = "Provider Error: $_"
    }

    return $result
}
