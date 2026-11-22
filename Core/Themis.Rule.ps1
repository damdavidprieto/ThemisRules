# ThemisRules: evaluation of a single rule, shared by Invoke-ThemisPolicy and Invoke-ThemisRule.
#
# Besides the provider itself, a rule can carry:
#   AppliesIf  conditions on facts about the machine, given by the caller with -Facts. When one is not
#              met the rule is NotApplicable and nothing is read or changed.
#   DependsOn  IDs of rules evaluated earlier in the same run. When one of them is not applicable,
#              failed, or (in Enforce mode) is still not compliant, the rule is Skipped.
#
# Statuses, besides the provider ones (Compliant, Non-Compliant, Fixed, Missing*, EnforceFailed, Error):
#   NotApplicable   the rule does not apply to this machine (AppliesIf, or the item does not exist)
#   NeedsElevation  the value can only be read as administrator
#   Manual          a Check rule that is not met: someone has to act (never changed by Enforce)
#   Unknown         a Check rule whose fact was not given
#   Skipped         a DependsOn rule was not applicable, failed or is not compliant

# Facts of the current evaluation, read by providers that need them (Check).
$script:ThemisFacts = @{}

function Get-ThemisFactValue {
    <#
    .SYNOPSIS
        Value of a fact from -Facts (a hashtable or an object), or $null when it is not given.
    #>
    [CmdletBinding()]
    param($Facts, [string]$Name)

    if ($null -eq $Facts) { return $null }
    if ($Facts -is [System.Collections.IDictionary]) { if ($Facts.Contains($Name)) { return $Facts[$Name] } else { return $null } }
    $property = $Facts.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Test-ThemisAppliesIf {
    <#
    .SYNOPSIS
        Checks the AppliesIf conditions of a rule against the facts. Returns $null when they are met,
        or the first condition that is not: @{ Fact; Expected; Actual; Reason }.
    .DESCRIPTION
        Each condition is "Fact": value (equal; text without case) or "Fact": { "lt"|"le"|"gt"|"ge"|"eq"|"ne": number }.
        A fact that was not given does not meet any condition.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory = $true)]$Rule, $Facts)

    $conditions = $Rule.AppliesIf
    if (-not $conditions) { return $null }
    $pairs = if ($conditions -is [System.Collections.IDictionary]) { @($conditions.GetEnumerator() | ForEach-Object { @{ Name = $_.Key; Value = $_.Value } }) }
    else { @($conditions.PSObject.Properties | ForEach-Object { @{ Name = $_.Name; Value = $_.Value } }) }

    foreach ($pair in $pairs) {
        $actual = Get-ThemisFactValue -Facts $Facts -Name $pair.Name
        $expected = $pair.Value
        $met = $false
        if ($null -eq $actual) { $met = $false }
        elseif ($expected -is [bool]) { $met = [bool]$actual -eq $expected }
        elseif ($expected -is [System.Collections.IDictionary] -or $expected -is [System.Management.Automation.PSCustomObject]) {
            $tests = if ($expected -is [System.Collections.IDictionary]) { @($expected.GetEnumerator() | ForEach-Object { @{ Name = $_.Key; Value = $_.Value } }) }
            else { @($expected.PSObject.Properties | ForEach-Object { @{ Name = $_.Name; Value = $_.Value } }) }
            $met = $true
            foreach ($test in $tests) {
                $a = 0.0; $b = 0.0
                if (-not ([double]::TryParse("$actual", [ref]$a) -and [double]::TryParse("$($test.Value)", [ref]$b))) { $met = $false; break }
                $ok = switch ($test.Name) {
                    'lt' { $a -lt $b } 'le' { $a -le $b } 'gt' { $a -gt $b } 'ge' { $a -ge $b } 'eq' { $a -eq $b } 'ne' { $a -ne $b }
                    default { throw "Unknown comparison '$($test.Name)' in AppliesIf. Use lt, le, gt, ge, eq or ne." }
                }
                if (-not $ok) { $met = $false; break }
            }
        }
        else { $met = "$actual" -eq "$expected" }

        if (-not $met) {
            $shown = if ($null -eq $actual) { 'not given' } else { "$actual" }
            return @{ Fact = $pair.Name; Expected = $expected; Actual = $actual; Reason = "Does not apply: $($pair.Name) is $shown." }
        }
    }
    return $null
}

function ConvertTo-ThemisPreviousList {
    <#
    .SYNOPSIS
        A provider's Previous (one restore rule or several) as a list of ordered dictionaries.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param($Previous)

    if ($null -eq $Previous) { return , @() }
    if ($Previous -is [System.Collections.IDictionary]) { return , @($Previous) }
    return , @($Previous | Where-Object { $null -ne $_ })
}

function Invoke-ThemisRuleCore {
    <#
    .SYNOPSIS
        Evaluates (and in Enforce mode applies) one rule: AppliesIf, DependsOn, then the provider.
    .DESCRIPTION
        Returns a result with Status, IsCompliant, Reason, Actual, Data (the values the provider read,
        as structured data), Previous (restore rules for what Enforce changed, as a list) and
        Condition (the AppliesIf condition that was not met). -Prior maps the IDs of rules evaluated
        earlier in the run to their results, for DependsOn.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)]$Rule,
        [ValidateSet('Audit', 'Enforce')][string]$Mode = 'Audit',
        $Facts,
        [hashtable]$Prior = @{}
    )

    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null; Data = $null; Previous = @(); Condition = $null; Restorable = $null; RequiresRestart = $null; Verified = $null }

    $condition = Test-ThemisAppliesIf -Rule $Rule -Facts $Facts
    if ($condition) {
        $result.Status = 'NotApplicable'; $result.IsCompliant = $true; $result.Reason = $condition.Reason; $result.Condition = $condition
        return [pscustomobject]$result
    }

    foreach ($dependency in @($Rule.DependsOn | Where-Object { $_ })) {
        $dep = $Prior["$dependency"]
        $problem = $null
        if (-not $dep) { $problem = 'was not evaluated before it' }
        elseif ($dep.Status -in 'NotApplicable', 'Skipped', 'Error', 'NeedsElevation', 'EnforceFailed', 'Unknown') { $problem = "is $($dep.Status)" }
        elseif ($Mode -eq 'Enforce' -and -not $dep.IsCompliant) { $problem = 'is not compliant' }
        if ($problem) {
            $result.Status = 'Skipped'
            $result.Reason = "Depends on $dependency, which $problem."
            $result.Condition = @{ DependsOn = "$dependency"; Status = $(if ($dep) { $dep.Status } else { $null }) }
            return [pscustomobject]$result
        }
    }

    if ($script:ProviderCache.Count -eq 0) { Initialize-ThemisProviders }
    $command = $script:ProviderCache[$Type]
    if (-not $command) { throw "No provider for rule type '$Type'. Get-ThemisProvider lists them." }

    $script:ThemisFacts = $Facts
    try { $res = & $command -Rule $Rule -Mode $Mode }
    finally { $script:ThemisFacts = @{} }
    # A provider returns one dictionary. If something it called also wrote to the pipeline (a COM method returning
    # $null, for example), the result arrives as a list: take the dictionary, or the status and the restore rules
    # of a change that did happen would be lost.
    if ($res -isnot [System.Collections.IDictionary]) {
        $res = @($res | Where-Object { $_ -is [System.Collections.IDictionary] }) | Select-Object -Last 1
        if (-not $res) { $res = @{ Status = 'Error'; Reason = "The $Type provider returned no result." } }
    }

    foreach ($key in 'Status', 'IsCompliant', 'Reason', 'Actual', 'Data') { if ($res.Contains($key)) { $result[$key] = $res[$key] } }
    if ($res.Contains('Previous')) { $result.Previous = ConvertTo-ThemisPreviousList $res.Previous }
    # A change that comes back without restore rules cannot be undone: say so instead of letting the caller
    # believe it can. Restorable is $true or $false for changes (Fixed, or a failed change that left restore
    # rules), and $null when nothing changed.
    if ($Mode -eq 'Enforce' -and $result.Status -eq 'Fixed') {
        # Whether the change needs a restart: the provider says so, or the rule does (RequiresRestart).
        if ($res.Contains('RequiresRestart')) { $result.RequiresRestart = [bool]$res.RequiresRestart }
        elseif ($Rule.RequiresRestart) { $result.RequiresRestart = $true }
        else { $result.RequiresRestart = $false }
        # Read it back: a change that a policy or a protection reverts at once is not really done.
        $script:ThemisFacts = $Facts
        try { $check = & $command -Rule $Rule -Mode 'Audit' }
        catch { $check = $null }
        finally { $script:ThemisFacts = @{} }
        if ($check -isnot [System.Collections.IDictionary]) { $check = @($check | Where-Object { $_ -is [System.Collections.IDictionary] }) | Select-Object -Last 1 }
        $result.Verified = [bool]($check -and $check['IsCompliant'])
        if (-not $result.Verified) {
            $result.Reason = "$($result.Reason) Reading it again does not show the change yet: it may need a restart, or a policy or protection may undo it.".Trim()
        }
    }
    if (@($result.Previous).Count) { $result.Restorable = $true }
    elseif ($Mode -eq 'Enforce' -and $result.Status -eq 'Fixed') {
        $result.Restorable = $false
        Write-Warning "[Themis] $($Rule.ID) ($Type) was changed, but the provider returned no restore rules: the change cannot be undone."
    }
    return [pscustomobject]$result
}
