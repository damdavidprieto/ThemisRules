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

    .PARAMETER InputObject
        Several rules at once, from the pipeline: objects or hashtables with Type and Rule. They share one read cache
        (the security policy and the audit policy are read once for all of them), facts are read once, and each
        result is passed to the next rules for DependsOn.

    .PARAMETER Mode
        Audit (check only, the default) or Enforce (apply the rule).

    .PARAMETER Facts
        Facts about the machine for AppliesIf and Check rules, as a hashtable or object. The built-in facts a rule
        uses and -Facts does not give are read from the machine (see Get-ThemisFact).

    .PARAMETER Prior
        Results of rules evaluated earlier, by ID, for DependsOn.

    .PARAMETER KeepReadCache
        Reuse what earlier calls read in bulk (the exported security policy, the audit policy and the facts) instead
        of reading it again. Use it while auditing many rules in a row; writes always refresh what they change.

    .PARAMETER NoFactCollection
        Do not read built-in facts from the machine.

    .EXAMPLE
        Invoke-ThemisRule -Type Service -Rule @{ ID = 'SVC-1'; Name = 'RemoteRegistry'; StartupType = 'Disabled' }

        Reports whether the Remote Registry service is disabled.

    .EXAMPLE
        $r = Invoke-ThemisRule -Type Registry -Rule $rule -Mode Enforce
        $r.Previous | ForEach-Object { Invoke-ThemisRule -Type Registry -Rule $_ -Mode Enforce }

        Applies a registry rule and then puts the previous values back.

    .EXAMPLE
        @(
            @{ Type = 'SecurityPolicy'; Rule = @{ ID = 'ACC-1'; Name = 'Length'; Key = 'MinimumPasswordLength'; Value = 14; Comparison = 'AtLeast' } }
            @{ Type = 'AuditPolicy'; Rule = @{ ID = 'AUD-1'; Name = 'Logon'; Subcategory = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Setting = 'SuccessAndFailure' } }
        ) | Invoke-ThemisRule

        Audits two rules, reading the security policy and the audit policy once.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'One')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'One')]
        [string]$Type,

        [Parameter(Mandatory = $true, ParameterSetName = 'One')]
        [object]$Rule,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Many')]
        [object]$InputObject,

        [ValidateSet('Audit', 'Enforce')]
        [string]$Mode = 'Audit',

        [object]$Facts = @{},

        [hashtable]$Prior = @{},

        [switch]$KeepReadCache,

        [switch]$NoFactCollection
    )

    begin {
        if ($script:ProviderCache.Count -eq 0) { Initialize-ThemisProviders }
        # By default each call (or each pipeline) reads the system again: cached reads of a previous call could be out of date.
        if (-not $KeepReadCache) { $script:ThemisRunCache = @{} }
        $known = @{}
        foreach ($key in $Prior.Keys) { $known[$key] = $Prior[$key] }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Many') {
            $item = if ($InputObject -is [System.Collections.IDictionary]) { [pscustomobject]$InputObject } else { $InputObject }
            $Type = "$($item.Type)"
            $Rule = $item.Rule
            if (-not $Type -or $null -eq $Rule) { throw 'Each item of -InputObject needs Type and Rule.' }
        }
        if (-not $script:ProviderCache.ContainsKey($Type)) {
            throw "No provider for rule type '$Type'. Available: $(($script:ProviderCache.Keys | Sort-Object) -join ', ')."
        }
        $ruleObject = if ($Rule -is [System.Collections.IDictionary]) { [pscustomobject]$Rule } else { $Rule }

        $ruleMode = $Mode
        if ($Mode -eq 'Enforce' -and -not $PSCmdlet.ShouldProcess("$Type rule $($ruleObject.ID) ($($ruleObject.Name))", 'Enforce')) {
            $ruleMode = 'Audit'
        }

        $ruleFacts = Resolve-ThemisFact -Facts $Facts -Rules @($ruleObject) -NoCollection:$NoFactCollection
        $res = Invoke-ThemisRuleCore -Type $Type -Rule $ruleObject -Mode $ruleMode -Facts $ruleFacts -Prior $known
        if ($ruleObject.ID) { $known["$($ruleObject.ID)"] = $res }
        [pscustomobject]@{
            ID              = $ruleObject.ID
            Type            = $Type
            Name            = $ruleObject.Name
            Severity        = Get-ThemisSeverity -Rule $ruleObject
            References      = @($ruleObject.References | Where-Object { $_ })
            Status          = $res.Status
            IsCompliant     = $res.IsCompliant
            Reason          = $res.Reason
            Actual          = $res.Actual
            Data            = $res.Data
            Previous        = @($res.Previous)
            Condition       = $res.Condition
            Restorable      = $res.Restorable
            RequiresRestart = $res.RequiresRestart
            Verified        = $res.Verified
        }
    }
}
