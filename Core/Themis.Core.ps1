# ThemisRules policy engine core.
# Compliance auditing and enforcement for Windows, driven by JSON policies.
#
# Discovers the rule providers loaded from Providers/ and dispatches rules to them.
#
# David Prieto

# Provider registry: rule type (e.g. "Registry") -> command that evaluates it.
$script:ProviderCache = @{}

function Initialize-ThemisProviders {
    <#
    .SYNOPSIS
        Registers the Invoke-Themis<Type>Rule provider functions of this module.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Private function; registers several providers.')]
    [CmdletBinding()]
    param()

    # Providers are the Invoke-Themis<Type>Rule functions dot-sourced from Providers/*.ps1.
    # Only functions defined by this module count: a function with a matching name defined
    # elsewhere in the session must not be able to register itself as a provider.
    $script:ProviderCache = @{}
    $thisModule = $ExecutionContext.SessionState.Module
    foreach ($command in Get-Command -Name 'Invoke-Themis*Rule' -CommandType Function) {
        if ($null -eq $thisModule -or $command.ScriptBlock.Module -ne $thisModule) { continue }
        if ($command.Name -match '^Invoke-Themis(.+)Rule$') {
            $script:ProviderCache[$matches[1]] = $command.Name
            Write-Verbose "[Themis] Registered Provider: $($matches[1]) -> $($command.Name)"
        }
    }
}

function Invoke-ThemisPolicy {
    <#
    .SYNOPSIS
        Checks a JSON policy or a shipped baseline against this machine and, in Enforce mode, applies it.

    .DESCRIPTION
        Reads the policy (a file, or a baseline shipped with the module: see Get-ThemisBaseline)
        and evaluates every rule with the provider for its section: RegistryRules, ServiceRules,
        ProcessRules, AuditPolicyRules, SecurityPolicyRules, UserRightsRules and FirewallProfileRules.
        It returns one result per rule
        with Timestamp, Policy, PolicyPath, ID, Type, Name, MacroLevel, Status, IsCompliant,
        Reason and Actual. Status is Compliant, Non-Compliant, Fixed, Missing*, EnforceFailed
        or Error.
        Audit mode (the default) only reads. Enforce mode changes the system to match the
        policy: it writes registry values, starts, stops, reconfigures or deletes services and
        stops processes. Enforce supports -WhatIf and -Confirm: rules you decline, or all rules
        with -WhatIf, are only audited. Run Enforce elevated for HKLM keys and services.
        Before changing anything, Enforce records the previous values: when at least one rule is
        changed, it saves them as a backup policy (see Get-ThemisBackup) and adds its path to the
        results in the Backup property. The backup is updated after every changed rule, so if the
        run stops halfway the values changed so far can still be restored; a value is also kept
        when its change fails partway. Restore-ThemisBackup puts the old values back. Stopped
        processes and deleted services cannot be restored.
        A policy runs with your permissions: only use policies from a source you trust.
        Sections without a provider are skipped with a warning.
        A rule with AppliesIf is NotApplicable when its conditions on -Facts are not met, and a rule
        with DependsOn is Skipped when a rule it depends on (evaluated earlier) is not applicable,
        failed, or in Enforce mode is still not compliant.

    .PARAMETER PolicyPath
        Path to the policy JSON file.

    .PARAMETER Baseline
        Name of a baseline shipped with the module, such as Windows-Workstation. Get-ThemisBaseline
        lists them.

    .PARAMETER Mode
        Audit (check only, the default) or Enforce (apply the policy).

    .PARAMETER MacroLevel
        Evaluate only rules up to this hardening level, L1 to L5. Rules without a level are
        always evaluated; rules with a level that is not L1 to L5 are skipped with a warning.

    .PARAMETER BackupPath
        Folder for the backups that Enforce writes. Defaults to ThemisRules\Backups under
        %ProgramData% in an elevated session (a folder only administrators can change) and under
        %LOCALAPPDATA% (or ~/.local/share) otherwise.

    .PARAMETER NoBackup
        Do not write a backup in Enforce mode.

    .PARAMETER Facts
        Facts about the machine (a hashtable or an object), used by the AppliesIf conditions of the
        rules and by Check rules, for example @{ HasPrinters = $false; OSBuild = 26100 }.

    .EXAMPLE
        Invoke-ThemisPolicy -Baseline Windows-Workstation -MacroLevel L1

        Audits this machine against the L1 rules of the shipped workstation baseline. Run it
        elevated: audit and security policy rules need administrator rights.

    .EXAMPLE
        Invoke-ThemisPolicy -PolicyPath .\baseline.json

        Audits every rule of your own policy file and returns the results.

    .EXAMPLE
        Invoke-ThemisPolicy -PolicyPath .\baseline.json -Mode Enforce -MacroLevel L1 -WhatIf

        Shows which L1 rules would be enforced, and audits them without changing anything.

    .EXAMPLE
        Invoke-ThemisPolicy -PolicyPath .\baseline.json | Where-Object { -not $_.IsCompliant } | Export-ThemisReport -Path .\gaps.html

        Saves the rules that do not comply as an HTML report.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Path')]
    [OutputType([pscustomobject[]], [object[]])]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Path')]
        [string]$PolicyPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Baseline')]
        [ArgumentCompleter({
                param($commandName, $parameterName, $wordToComplete)
                $null = $commandName, $parameterName
                Get-ChildItem -Path (Join-Path (Split-Path (Get-Module ThemisRules).Path) 'Baselines') -Filter '*.json' |
                    Where-Object BaseName -Like "$wordToComplete*" | ForEach-Object BaseName
            })]
        [ValidatePattern('^[A-Za-z0-9._-]+$')]
        [string]$Baseline,

        [ValidateSet('Audit', 'Enforce')]
        [string]$Mode = 'Audit',

        [ValidatePattern('^L[1-5]$')]
        [string]$MacroLevel = $null,

        [string]$BackupPath = (Get-ThemisBackupFolder),

        [switch]$NoBackup,

        [object]$Facts = @{}
    )

    # 1. Initialize
    if ($script:ProviderCache.Count -eq 0) { Initialize-ThemisProviders }
    $script:ThemisRunCache = @{}

    if ($PSCmdlet.ParameterSetName -eq 'Baseline') {
        $PolicyPath = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'Baselines') "$Baseline.json"
        if (-not (Test-Path -LiteralPath $PolicyPath -PathType Leaf)) {
            $available = (Get-ThemisBaseline).Name -join ', '
            Write-Error "[Themis] Baseline '$Baseline' not found. Available baselines: $available"
            return $null
        }
    }

    if (-not (Test-Path -LiteralPath $PolicyPath -PathType Leaf)) {
        Write-Error "[Themis] Policy not found: $PolicyPath"
        return $null
    }

    # -Encoding UTF8: Windows PowerShell 5.1 reads files without a BOM as ANSI otherwise.
    $policy = Get-Content -LiteralPath $PolicyPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $policyName = if ($policy.Meta.Name) { $policy.Meta.Name } else { [System.IO.Path]::GetFileNameWithoutExtension($PolicyPath) }
    $policyVersion = if ($policy.Meta.Version) { $policy.Meta.Version } else { "1.0.0" }

    Write-Verbose "Loaded Policy: $policyName v$policyVersion"
    if ($MacroLevel) {
        Write-Verbose "Filtering by MacroLevel: $MacroLevel"
    }

    # 2. Flatten Rules with MacroLevel Filtering
    $allRules = @()
    $targetLevel = if ($MacroLevel) { [int]($MacroLevel -replace 'L', '') } else { 999 }

    # Iterate known provider types in the JSON
    foreach ($prop in $policy.PSObject.Properties) {
        if ($prop.Name -match "(.+)Rules") {
            $type = $matches[1] # "Registry" from "RegistryRules"

            if (-not $script:ProviderCache.ContainsKey($type)) {
                Write-Warning "[Themis] No provider for '$($prop.Name)'; its rules are skipped."
            }
            else {
                foreach ($rule in $prop.Value) {
                    # MacroLevel filter. Rules without a level are always evaluated, as documented.
                    # A level that is not L1-L5 is a mistake in the policy: with -MacroLevel the rule
                    # is skipped with a warning instead of being applied at a level nobody chose.
                    $ruleLevel = 0
                    if ($rule.MacroLevel) {
                        if ("$($rule.MacroLevel)" -match '^L([1-5])$') { $ruleLevel = [int]$matches[1] }
                        elseif ($MacroLevel) {
                            Write-Warning "[Themis] Rule $($rule.ID) has an invalid MacroLevel '$($rule.MacroLevel)' (use L1-L5); it is skipped."
                            continue
                        }
                    }

                    # Only include rules <= target level
                    if ($ruleLevel -le $targetLevel) {
                        # Inject Type and Metadata into Rule Object
                        $rule | Add-Member -MemberType NoteProperty -Name "_ProviderType" -Value $type -Force
                        $rule | Add-Member -MemberType NoteProperty -Name "_PolicyName" -Value $policyName -Force
                        $rule | Add-Member -MemberType NoteProperty -Name "_PolicyPath" -Value $PolicyPath -Force
                        $allRules += $rule
                    }
                    else {
                        Write-Verbose "Skipping rule $($rule.ID) (Level: $($rule.MacroLevel), Target: $MacroLevel)"
                    }
                }
            }
        }
    }

    Write-Verbose "Total rules after filtering: $($allRules.Count)"
    $results = @()
    $backupRules = [System.Collections.Generic.List[object]]::new()
    $backupFile = $null
    $prior = @{}

    # 3. Execution

    foreach ($rule in $allRules) {
        $type = $rule._ProviderType

        Write-Verbose "Processing Rule: $($rule.ID) ($type)"

        # Enforce changes the system: each rule asks ShouldProcess, and is only audited when
        # declined or when -WhatIf is used.
        $ruleMode = $Mode
        if ($Mode -eq 'Enforce' -and -not $PSCmdlet.ShouldProcess("$type rule $($rule.ID) ($($rule.Name))", 'Enforce')) {
            $ruleMode = 'Audit'
        }

        try {
            $res = Invoke-ThemisRuleCore -Type $type -Rule $rule -Mode $ruleMode -Facts $Facts -Prior $prior
            $prior["$($rule.ID)"] = $res

            # Enrich Result with Enhanced Metadata
            $obj = [PSCustomObject]@{
                Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Policy      = $rule._PolicyName
                PolicyPath  = $rule._PolicyPath
                ID          = $rule.ID
                Type        = $type
                Name        = $rule.Name
                MacroLevel  = $rule.MacroLevel
                Status      = $res.Status
                IsCompliant = $res.IsCompliant
                Reason      = $res.Reason
                Actual      = $res.Actual
                Backup      = $null
            }
            $results += $obj

            foreach ($previous in $res.Previous) {
                $restore = [ordered]@{ ID = $rule.ID }
                if (-not $previous.Contains('Name')) { $restore.Name = "Restore: $($rule.Name)" }
                foreach ($key in $previous.Keys) { $restore[$key] = $previous[$key] }
                $backupRules.Add([pscustomobject]@{ Section = "${type}Rules"; Rule = $restore; Result = $obj })
            }
            if (@($res.Previous).Count -and -not $NoBackup) {
                # The backup is written after every change, not at the end: if the run stops
                # halfway (error, Ctrl+C, power cut), the values changed so far can still be restored.
                $backupFile = Save-ThemisBackup -Folder $BackupPath -PolicyName $policyName -PolicyPath $PolicyPath -Entries $backupRules -File $backupFile -Confirm:$false
                foreach ($entry in $backupRules) { $entry.Result.Backup = $backupFile }
            }

        }
        catch {
            Write-Error "Dispatch Error ($type / $($rule.ID)): $_"
        }
    }

    # 4. The backup of the values Enforce changed was written as each rule ran (see above).
    if ($backupFile) {
        Write-Verbose "Previous values saved to $backupFile. Restore them with Restore-ThemisBackup -Path '$backupFile'."
    }

    return $results
}

function Get-ThemisBackupFolder {
    <#
    .SYNOPSIS
        Default folder for Enforce backups.
    .DESCRIPTION
        Elevated sessions on Windows use ThemisRules\Backups under %ProgramData%, a folder that only
        administrators and SYSTEM can change: a backup is restored as administrator, so a program
        running without elevation must not be able to edit it. Other sessions use ThemisRules\Backups
        under %LOCALAPPDATA% (or ~/.local/share); their changes are limited to what that user can
        already do.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ((Test-ThemisElevated) -and $env:ProgramData) {
        return (Join-Path (Join-Path $env:ProgramData 'ThemisRules') 'Backups')
    }
    $base = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $HOME '.local/share' }
    return (Join-Path (Join-Path $base 'ThemisRules') 'Backups')
}

function Initialize-ThemisBackupFolder {
    <#
    .SYNOPSIS
        Creates the backup folder. When elevated on Windows, it is owned by Administrators and only
        SYSTEM and Administrators can change it (inherited permissions are removed).
    .DESCRIPTION
        Only the default elevated folder, under %ProgramData%\ThemisRules, is protected. The
        protection is applied every time, also when the folder already exists: any user can create
        folders in %ProgramData%, so a folder made beforehand by someone else is taken over instead
        of trusted. The ThemisRules folder above it gets the same protection.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Folder)

    if (-not $PSCmdlet.ShouldProcess($Folder, 'Create backup folder')) { return }
    $null = [System.IO.Directory]::CreateDirectory($Folder)
    # Only the default elevated folder is protected. A folder given with -BackupPath keeps its
    # permissions: changing them could lock its owner out of their own folder.
    if (-not (Test-ThemisElevated) -or -not $env:ProgramData) { return }
    $root = [System.IO.Path]::GetFullPath((Join-Path $env:ProgramData 'ThemisRules'))
    $full = [System.IO.Path]::GetFullPath($Folder).TrimEnd('\')
    if ($full -ine $root -and -not $full.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { return }

    $targets = @($root)
    if ($full -ine $root) { $targets += $full }
    foreach ($dir in $targets) {
        $security = New-Object System.Security.AccessControl.DirectorySecurity
        $security.SetSecurityDescriptorSddlForm('O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
        Set-Acl -LiteralPath $dir -AclObject $security -ErrorAction Stop
    }
}

function Test-ThemisTrustedPath {
    <#
    .SYNOPSIS
        True when only SYSTEM, Administrators and TrustedInstaller can change the file or folder.
    .DESCRIPTION
        Checks the owner and every allow entry that grants write, delete, permission or ownership
        rights. Used before restoring a backup as administrator: a file that a program running
        without elevation can edit must not decide what an elevated session writes. Inherit-only
        entries do not apply to the object itself and are ignored. Always true off Windows.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) { return $true }
    $trusted = 'S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    # WriteData, AppendData, WriteExtendedAttributes, DeleteSubdirectoriesAndFiles, WriteAttributes,
    # Delete, ChangePermissions, TakeOwnership, GenericAll and GenericWrite.
    $writeMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $trusted) { return $false }
        foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ("$($ace.AccessControlType)" -ne 'Allow') { continue }
            if ($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
            if (([int64]$ace.FileSystemRights -band $writeMask) -and $ace.IdentityReference.Value -notin $trusted) { return $false }
        }
        return $true
    }
    catch {
        return $false
    }
}

function Save-ThemisBackup {
    <#
    .SYNOPSIS
        Writes the previous values recorded by Enforce as a policy file and returns its path.
    .DESCRIPTION
        Called after every changed rule with all the entries recorded so far. The first call picks a
        new file name (time to the millisecond plus a random suffix, so two runs never share a file);
        later calls of the same run pass it in -File and replace its content. The file is written
        under a temporary name and then moved into place, so it is never left half written.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$Folder,
        [Parameter(Mandatory = $true)][string]$PolicyName,
        [Parameter(Mandatory = $true)][string]$PolicyPath,
        [Parameter(Mandatory = $true)][object[]]$Entries,
        [string]$File
    )

    $stamp = Get-Date
    if (-not $File) {
        Initialize-ThemisBackupFolder -Folder $Folder -Confirm:$false
        $safeName = ($PolicyName -replace '[^A-Za-z0-9._-]+', '-').Trim('-')
        $suffix = [guid]::NewGuid().ToString('N').Substring(0, 6)
        $File = Join-Path $Folder ("{0}-{1}-{2}.json" -f $stamp.ToString('yyyyMMdd-HHmmss-fff'), $suffix, $safeName)
    }

    $backup = [ordered]@{
        Meta = [ordered]@{
            Name         = "Backup before enforcing $PolicyName"
            Version      = '1.0.0'
            Created      = $stamp.ToString('yyyy-MM-dd HH:mm:ss')
            SourcePolicy = $PolicyPath
            Description  = 'Values that Invoke-ThemisPolicy -Mode Enforce changed, as they were before. Apply it with Restore-ThemisBackup to put them back.'
        }
    }
    foreach ($group in $Entries | Group-Object Section) {
        $backup[$group.Name] = @($group.Group | ForEach-Object { $_.Rule })
    }

    if ($PSCmdlet.ShouldProcess($File, 'Save backup of previous values')) {
        $temp = "$File.tmp"
        $backup | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $temp -Encoding UTF8
        Move-Item -LiteralPath $temp -Destination $File -Force
    }
    return $File
}
