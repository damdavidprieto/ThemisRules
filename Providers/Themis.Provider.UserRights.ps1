# ThemisRules UserRights provider: User Rights Assignment of the local security policy (secedit).
#
# Principals are SIDs only (for example S-1-5-32-544 for Administrators): names depend on the
# Windows language and could not be validated. Comparison:
#   Equal     the right is held by exactly these principals (an empty list means nobody)
#   Includes  these principals must hold the right (others may too), e.g. deny rights
#   Excludes  none of these principals may hold the right
# On domain-joined machines Group Policy usually defines user rights and overrides local changes.

function Invoke-ThemisUserRightsRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null }

    $right = "$($Rule.Right)"
    if ($right -notmatch '^Se[A-Za-z]+(Privilege|Right)$') {
        $result.Status = 'Error'
        $result.Reason = "Right must be a user right constant such as SeDebugPrivilege or SeNetworkLogonRight: '$right'."
        return $result
    }
    $comparison = if ($Rule.Comparison) { "$($Rule.Comparison)" } else { 'Equal' }
    if ($comparison -notin 'Equal', 'Includes', 'Excludes') {
        $result.Status = 'Error'
        $result.Reason = "Comparison must be Equal, Includes or Excludes: '$comparison'."
        return $result
    }
    $wanted = @($Rule.Principals | Where-Object { "$_" } | ForEach-Object { "$_".ToUpperInvariant() })
    $badSid = $wanted | Where-Object { $_ -notmatch '^S-1-[0-9]+(-[0-9]+)+$' }
    if ($badSid) {
        $result.Status = 'Error'
        $result.Reason = "Principals must be SIDs such as S-1-5-32-544, not names: '$($badSid -join "', '")'."
        return $result
    }
    if (-not (Test-ThemisElevated)) {
        $result.Status = 'Error'
        $result.Reason = 'Reading user rights requires an elevated session (Run as administrator).'
        return $result
    }

    try {
        $rights = Get-ThemisUserRight
        $current = @(if ($rights.ContainsKey($right)) { $rights[$right] })
        $result.Actual = if ($current) { $current -join ', ' } else { '(nobody)' }

        $missing = @($wanted | Where-Object { $_ -notin $current })
        $extra = @($current | Where-Object { $_ -notin $wanted })
        $present = @($wanted | Where-Object { $_ -in $current })
        $compliant = switch ($comparison) {
            'Equal' { $missing.Count -eq 0 -and $extra.Count -eq 0 }
            'Includes' { $missing.Count -eq 0 }
            'Excludes' { $present.Count -eq 0 }
        }
        $expected = if ($wanted) { $wanted -join ', ' } else { 'nobody' }

        if ($compliant) {
            $result.Status = 'Compliant'
            $result.IsCompliant = $true
            $result.Reason = "$right ($comparison $expected) is met."
            return $result
        }

        $result.Status = 'Non-Compliant'
        $details = @()
        if ($comparison -ne 'Excludes' -and $missing) { $details += "missing $($missing -join ', ')" }
        if ($comparison -eq 'Equal' -and $extra) { $details += "not allowed $($extra -join ', ')" }
        if ($comparison -eq 'Excludes' -and $present) { $details += "must not include $($present -join ', ')" }
        $result.Reason = "${right}: $($details -join '; ')."

        if ($Mode -eq 'Enforce') {
            $target = switch ($comparison) {
                'Equal' { $wanted }
                'Includes' { @($current) + $missing }
                'Excludes' { $current | Where-Object { $_ -notin $wanted } }
            }
            $target = @($target | Sort-Object -Unique)
            # Recorded before the change, so the backup covers it even if the read-back fails.
            $result.Previous = [ordered]@{ Right = $right; Principals = @($current); Comparison = 'Equal' }
            Set-ThemisUserRight -Right $right -Principals $target -Confirm:$false

            $after = @((Get-ThemisUserRight)[$right])
            if ((@($after | Sort-Object) -join ',') -eq ($target -join ',')) {
                $result.Status = 'Fixed'
                $result.IsCompliant = $true
                $result.Reason = "$right assigned to $(if ($target) { $target -join ', ' } else { 'nobody' })."
                $result.Actual = if ($after) { $after -join ', ' } else { '(nobody)' }
            }
            else {
                $result.Status = 'EnforceFailed'
                $result.Reason = "$right is still assigned to $($after -join ', '); a domain Group Policy may override it."
            }
        }
    }
    catch {
        $result.Status = 'Error'
        $result.Reason = "Provider Error: $_"
    }

    return $result
}
