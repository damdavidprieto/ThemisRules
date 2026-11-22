# ThemisRules FirewallRule provider: one Windows Firewall rule for a program, owned by ThemisRules.
#
#   DisplayName  Name of the rule. Themis only touches rules in its own group (ThemisRules), so a rule of
#                Windows or of another program with the same name is never changed or removed.
#   Program      Path of the program; environment variables such as %SystemRoot% are allowed.
#   Direction    Outbound (default) or Inbound.
#   Action       Block (default) or Allow.
#   Ensure       Present (default) or Absent.
# For example, blocking outbound connections of mshta.exe or wscript.exe stops a script from downloading the rest
# of an attack. Changing firewall rules needs an elevated session.

$script:ThemisFirewallGroup = 'ThemisRules'

function Get-ThemisFirewallRule {
    <#
    .SYNOPSIS
        The ThemisRules firewall rule with that name ({ Direction; Action; Program; Enabled }), or $null. Separate so the tests can mock it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$DisplayName)

    $rule = @(Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue | Where-Object Group -EQ $script:ThemisFirewallGroup) | Select-Object -First 1
    if (-not $rule) { return $null }
    $app = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
    return [pscustomobject]@{ Direction = "$($rule.Direction)"; Action = "$($rule.Action)"; Program = "$($app.Program)"; Enabled = "$($rule.Enabled)" -eq 'True' }
}

function Set-ThemisFirewallRule {
    <#
    .SYNOPSIS
        Creates (replacing any ThemisRules rule with the same name) or removes a ThemisRules firewall rule.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][ValidateSet('Present', 'Absent')][string]$Ensure,
        [string]$Program,
        [string]$Direction = 'Outbound',
        [string]$Action = 'Block'
    )

    if (-not $PSCmdlet.ShouldProcess($DisplayName, "Make the firewall rule $Ensure")) { return }
    Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue | Where-Object Group -EQ $script:ThemisFirewallGroup | Remove-NetFirewallRule -ErrorAction Stop
    if ($Ensure -eq 'Present') {
        $null = New-NetFirewallRule -DisplayName $DisplayName -Group $script:ThemisFirewallGroup -Program $Program -Direction $Direction -Action $Action -Profile Any -Enabled True -ErrorAction Stop
    }
}

function Invoke-ThemisFirewallRuleRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null }
    $name = "$($Rule.DisplayName)"
    $ensure = if ($Rule.Ensure) { "$($Rule.Ensure)" } else { 'Present' }
    $direction = if ($Rule.Direction) { "$($Rule.Direction)" } else { 'Outbound' }
    $action = if ($Rule.Action) { "$($Rule.Action)" } else { 'Block' }
    $program = "$($Rule.Program)"
    $problem = $null
    if ($name -notmatch '^[\w .,()+-]{1,200}$') { $problem = "DisplayName must be a plain name: '$name'." }
    elseif ($ensure -notin 'Present', 'Absent') { $problem = "Ensure must be Present or Absent: '$ensure'." }
    elseif ($direction -notin 'Outbound', 'Inbound') { $problem = "Direction must be Outbound or Inbound: '$direction'." }
    elseif ($action -notin 'Block', 'Allow') { $problem = "Action must be Block or Allow: '$action'." }
    elseif ($ensure -eq 'Present' -and $program -notmatch '^(%\w+%|[A-Za-z]:)\\[^"<>|*?]+\.exe$') { $problem = "Program must be the full path of an .exe (environment variables allowed): '$program'." }
    if ($problem) { $result.Status = 'Error'; $result.Reason = $problem; return $result }

    try {
        $current = Get-ThemisFirewallRule -DisplayName $name
        $result.Actual = if ($current) { "$($current.Action) $($current.Direction) $($current.Program)" } else { 'Missing' }
        $result.Data = @{ Exists = [bool]$current; Rule = $current }
        $same = $current -and $current.Enabled -and $current.Direction -eq $direction -and $current.Action -eq $action -and
            [string]::Equals([Environment]::ExpandEnvironmentVariables($current.Program), [Environment]::ExpandEnvironmentVariables($program), 'OrdinalIgnoreCase')
        $compliant = if ($ensure -eq 'Present') { [bool]$same } else { -not $current }
        if ($compliant) {
            $result.Status = 'Compliant'
            $result.IsCompliant = $true
            $result.Reason = if ($ensure -eq 'Present') { "Firewall rule '$name' is in place ($action $direction for $program)." } else { "There is no ThemisRules firewall rule '$name'." }
            return $result
        }
        $result.Status = 'Non-Compliant'
        $result.Reason = if ($ensure -eq 'Present') { "Firewall rule '$name' $(if ($current) { 'is different' } else { 'is missing' }); required: $action $direction for $program." } else { "Firewall rule '$name' exists; required: none." }
        if ($Mode -ne 'Enforce') { return $result }
        if (-not (Test-ThemisElevated)) {
            $result.Status = 'NeedsElevation'
            $result.Reason = 'Changing firewall rules requires an elevated session (Run as administrator).'
            return $result
        }

        Set-ThemisFirewallRule -DisplayName $name -Ensure $ensure -Program $program -Direction $direction -Action $action -Confirm:$false
        $after = Get-ThemisFirewallRule -DisplayName $name
        $ok = if ($ensure -eq 'Present') { $after -and $after.Action -eq $action -and $after.Direction -eq $direction } else { -not $after }
        if (-not $ok) {
            $result.Status = 'EnforceFailed'
            $result.Reason = "Firewall rule '$name' did not change."
            return $result
        }
        $result.Previous = if ($current) { [ordered]@{ DisplayName = $name; Ensure = 'Present'; Program = $current.Program; Direction = $current.Direction; Action = $current.Action } }
        else { [ordered]@{ DisplayName = $name; Ensure = 'Absent' } }
        $result.Status = 'Fixed'
        $result.IsCompliant = $true
        $result.Reason = if ($ensure -eq 'Present') { "Firewall rule '$name' now does $action $direction for $program." } else { "Firewall rule '$name' removed." }
    }
    catch {
        $result.Status = 'Error'
        $result.Reason = "Provider Error: $_"
    }
    return $result
}
