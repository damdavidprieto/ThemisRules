# ThemisRules SecurityPolicy provider: password, account lockout and other [System Access]
# settings of the local security policy (secedit).
#
# Only the keys below are accepted and values must be whole numbers, so a policy cannot write
# anything else into the security template. On domain-joined machines the domain's Group
# Policy usually defines these values and overrides local changes.

$script:ThemisSecurityPolicyKeys = @(
    'MinimumPasswordAge', 'MaximumPasswordAge', 'MinimumPasswordLength', 'PasswordComplexity',
    'PasswordHistorySize', 'LockoutBadCount', 'ResetLockoutCount', 'LockoutDuration',
    'AllowAdministratorLockout', 'RequireLogonToChangePassword', 'ForceLogoffWhenHourExpire',
    'ClearTextPassword', 'LSAAnonymousNameLookup', 'EnableAdminAccount', 'EnableGuestAccount'
)

function Invoke-ThemisSecurityPolicyRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null }

    $key = "$($Rule.Key)"
    if ($key -notin $script:ThemisSecurityPolicyKeys) {
        $result.Status = 'Error'
        $result.Reason = "Key '$key' is not supported. Supported keys: $($script:ThemisSecurityPolicyKeys -join ', ')."
        return $result
    }
    $value = 0
    if (-not [int]::TryParse("$($Rule.Value)", [ref]$value)) {
        $result.Status = 'Error'
        $result.Reason = "Value must be a whole number: '$($Rule.Value)'."
        return $result
    }
    if (-not (Test-ThemisElevated)) {
        $result.Status = 'Error'
        $result.Reason = 'Reading the local security policy requires an elevated session (Run as administrator).'
        return $result
    }

    try {
        $policy = Get-ThemisSecurityPolicy
        $current = if ($policy.ContainsKey($key)) { $policy[$key] } else { $null }
        $result.Actual = $current
        $check = Test-ThemisValue -Actual $current -Rule $Rule

        if ($check.Match) {
            $result.Status = 'Compliant'
            $result.IsCompliant = $true
            $result.Reason = "$key is $current (required: $($check.Expected))."
            return $result
        }

        $result.Status = 'Non-Compliant'
        $shown = if ($null -eq $current) { 'not defined' } else { $current }
        $result.Reason = "$key is $shown; required: $($check.Expected)."

        if ($Mode -eq 'Enforce') {
            Set-ThemisSecurityPolicy -Settings @{ $key = $value } -Confirm:$false
            $after = (Get-ThemisSecurityPolicy)[$key]
            if ((Test-ThemisValue -Actual $after -Rule $Rule).Match) {
                $result.Status = 'Fixed'
                $result.IsCompliant = $true
                $result.Reason = "$key set to $value."
                $result.Actual = $after
            }
            else {
                $result.Status = 'EnforceFailed'
                $result.Reason = "$key is still $after; a domain Group Policy may override it."
            }
        }
    }
    catch {
        $result.Status = 'Error'
        $result.Reason = "Provider Error: $_"
    }

    return $result
}
