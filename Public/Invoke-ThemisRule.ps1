function Invoke-ThemisRule {
    <#
    .SYNOPSIS
        Checks one rule against this machine and, in Enforce mode, applies it. For tools that keep
        their own history.

    .DESCRIPTION
        Evaluates a single rule with the provider for -Type (Registry, Service, Feature,
        SecureFolder, AuditPolicy, SecurityPolicy, UserRights, FirewallProfile, Process or Check),
        the same way Invoke-ThemisPolicy does for each rule of a policy, and returns the result
        with ID, Type, Name, Status, IsCompliant, Reason, Actual, Data, Previous, Condition and Restorable.
        Data holds what the provider read as structured values (for example the startup type and
        state of a service), so the caller can show it in its own words. Previous lists the
        restore rules for what Enforce changed: passing each of them back to Invoke-ThemisRule
        with -Mode Enforce puts the old values back, which is how Restore-ThemisBackup works.
        Unlike Invoke-ThemisPolicy, it saves no backup: the caller keeps Previous. Restorable is $true when
        there are restore rules, $false when Enforce changed the system and the provider returned none (it
        also writes a warning), and $null when nothing changed.
        AppliesIf conditions are checked against -Facts. DependsOn uses -Prior, the results of
        earlier rules by ID. Enforce supports -WhatIf and -Confirm; a declined rule is only audited.

    .PARAMETER Type
        Rule type, as listed by Get-ThemisProvider: the section name of a policy without "Rules".

    .PARAMETER Rule
        The rule: a hashtable or object with the fields of that type (see the README).

    .PARAMETER Mode
        Audit (check only, the default) or Enforce (apply the rule).

    .PARAMETER Facts
        Facts about the machine for AppliesIf and Check rules, as a hashtable or object.

    .PARAMETER Prior
        Results of rules evaluated earlier, by ID, for DependsOn.

    .PARAMETER KeepReadCache
        Reuse what earlier calls read in bulk (the exported security policy and audit policy) instead of
        reading it again. Use it while auditing many rules in a row; writes always refresh what they change.

    .EXAMPLE
        Invoke-ThemisRule -Type Service -Rule @{ ID = 'SVC-1'; Name = 'RemoteRegistry'; StartupType = 'Disabled' }

        Reports whether the Remote Registry service is disabled.

    .EXAMPLE
        $r = Invoke-ThemisRule -Type Registry -Rule $rule -Mode Enforce
        $r.Previous | ForEach-Object { Invoke-ThemisRule -Type Registry -Rule $_ -Mode Enforce }

        Applies a registry rule and then puts the previous values back.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [object]$Rule,

        [ValidateSet('Audit', 'Enforce')]
        [string]$Mode = 'Audit',

        [object]$Facts = @{},

        [hashtable]$Prior = @{},

        [switch]$KeepReadCache
    )

    if ($script:ProviderCache.Count -eq 0) { Initialize-ThemisProviders }
    if (-not $script:ProviderCache.ContainsKey($Type)) {
        throw "No provider for rule type '$Type'. Available: $(($script:ProviderCache.Keys | Sort-Object) -join ', ')."
    }
    $ruleObject = if ($Rule -is [System.Collections.IDictionary]) { [pscustomobject]$Rule } else { $Rule }

    $ruleMode = $Mode
    if ($Mode -eq 'Enforce' -and -not $PSCmdlet.ShouldProcess("$Type rule $($ruleObject.ID) ($($ruleObject.Name))", 'Enforce')) {
        $ruleMode = 'Audit'
    }

    # By default each call reads the system again: cached reads of a previous call could be out of date.
    if (-not $KeepReadCache) { $script:ThemisRunCache = @{} }
    $res = Invoke-ThemisRuleCore -Type $Type -Rule $ruleObject -Mode $ruleMode -Facts $Facts -Prior $Prior
    return [pscustomobject]@{
        ID          = $ruleObject.ID
        Type        = $Type
        Name        = $ruleObject.Name
        Status      = $res.Status
        IsCompliant = $res.IsCompliant
        Reason      = $res.Reason
        Actual      = $res.Actual
        Data        = $res.Data
        Previous    = @($res.Previous)
        Condition   = $res.Condition
        Restorable  = $res.Restorable
    }
}
