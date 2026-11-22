BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../ThemisRules.psd1') -Force
}

Describe 'Invoke-ThemisRule' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    BeforeEach {
        New-Item -Path 'TestRegistry:\ThemisRule' -Force | Out-Null
        New-ItemProperty -Path 'TestRegistry:\ThemisRule' -Name 'Level' -Value 1 -PropertyType DWord | Out-Null
    }

    It 'audits one rule and returns structured data' {
        $r = Invoke-ThemisRule -Type Registry -Rule @{ ID = 'R1'; Name = 'Level'; Path = 'TestRegistry:\ThemisRule'; ValueName = 'Level'; Value = 2; Type = 'DWord' }
        $r.Status | Should -Be 'Non-Compliant'
        $r.Data.Keys[0].Value | Should -Be 1
        @($r.Previous).Count | Should -Be 0
    }

    It 'applies it and returns the restore rules, which put the old value back' {
        $r = Invoke-ThemisRule -Type Registry -Rule @{ ID = 'R1'; Name = 'Level'; Path = 'TestRegistry:\ThemisRule'; ValueName = 'Level'; Value = 2; Type = 'DWord' } -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        (Get-ItemProperty 'TestRegistry:\ThemisRule').Level | Should -Be 2
        foreach ($previous in $r.Previous) { $null = Invoke-ThemisRule -Type Registry -Rule $previous -Mode Enforce }
        (Get-ItemProperty 'TestRegistry:\ThemisRule').Level | Should -Be 1
    }

    It 'changes nothing with -WhatIf' {
        $null = Invoke-ThemisRule -Type Registry -Rule @{ ID = 'R1'; Name = 'Level'; Path = 'TestRegistry:\ThemisRule'; ValueName = 'Level'; Value = 2; Type = 'DWord' } -Mode Enforce -WhatIf
        (Get-ItemProperty 'TestRegistry:\ThemisRule').Level | Should -Be 1
    }

    It 'refuses an unknown type' {
        { Invoke-ThemisRule -Type Nope -Rule @{ ID = 'X' } } | Should -Throw '*No provider*'
    }
}

Describe 'AppliesIf and DependsOn' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    BeforeEach { New-Item -Path 'TestRegistry:\ThemisCond' -Force | Out-Null }

    It 'is NotApplicable when a fact does not meet the condition, and reports which' {
        $rule = @{ ID = 'C1'; Name = 'x'; Path = 'TestRegistry:\ThemisCond'; ValueName = 'V'; Value = 1; Type = 'DWord'; AppliesIf = @{ HasPrinters = $false } }
        $r = Invoke-ThemisRule -Type Registry -Rule $rule -Mode Enforce -Facts @{ HasPrinters = $true }
        $r.Status | Should -Be 'NotApplicable'
        $r.Condition.Fact | Should -Be 'HasPrinters'
        (Get-ItemProperty 'TestRegistry:\ThemisCond').PSObject.Properties.Name | Should -Not -Contain 'V'
    }

    It 'supports numeric comparisons and treats a missing fact as not met' {
        $rule = [pscustomobject]@{ ID = 'C2'; Name = 'x'; Path = 'TestRegistry:\ThemisCond'; ValueName = 'V'; Value = 1; Type = 'DWord'; AppliesIf = [pscustomobject]@{ OSBuild = [pscustomobject]@{ lt = 26100 } } }
        (Invoke-ThemisRule -Type Registry -Rule $rule -Facts @{ OSBuild = 22631 }).Status | Should -Be 'MissingValue'
        (Invoke-ThemisRule -Type Registry -Rule $rule -Facts @{ OSBuild = 26200 }).Status | Should -Be 'NotApplicable'
        (Invoke-ThemisRule -Type Registry -Rule $rule).Status | Should -Be 'NotApplicable'
    }

    It 'skips a rule whose dependency is not applicable, in a policy' {
        $policy = Join-Path $TestDrive 'depends.json'
        @{
            Meta          = @{ Name = 'Depends'; Version = '1.0.0' }
            RegistryRules = @(
                @{ ID = 'D1'; Name = 'base'; Path = 'TestRegistry:\ThemisCond'; ValueName = 'A'; Value = 1; Type = 'DWord'; AppliesIf = @{ Ready = $true } }
                @{ ID = 'D2'; Name = 'needs base'; Path = 'TestRegistry:\ThemisCond'; ValueName = 'B'; Value = 1; Type = 'DWord'; DependsOn = @('D1') }
            )
        } | ConvertTo-Json -Depth 6 | Set-Content $policy
        $results = Invoke-ThemisPolicy -PolicyPath $policy -Mode Enforce -Facts @{ Ready = $false } -NoBackup
        ($results | Where-Object ID -EQ 'D2').Status | Should -Be 'Skipped'
        (Get-ItemProperty 'TestRegistry:\ThemisCond').PSObject.Properties.Name | Should -Not -Contain 'B'
    }

    It 'applies a dependent rule once its dependency is fixed' {
        $policy = Join-Path $TestDrive 'depends-ok.json'
        @{
            Meta          = @{ Name = 'Depends'; Version = '1.0.0' }
            RegistryRules = @(
                @{ ID = 'D1'; Name = 'base'; Path = 'TestRegistry:\ThemisCond'; ValueName = 'A'; Value = 1; Type = 'DWord' }
                @{ ID = 'D2'; Name = 'needs base'; Path = 'TestRegistry:\ThemisCond'; ValueName = 'B'; Value = 1; Type = 'DWord'; DependsOn = @('D1') }
            )
        } | ConvertTo-Json -Depth 6 | Set-Content $policy
        $results = Invoke-ThemisPolicy -PolicyPath $policy -Mode Enforce -NoBackup
        $results.Status | Should -Be @('Fixed', 'Fixed')
    }
}

Describe 'Registry rules for hardening tools' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    BeforeEach {
        New-Item -Path 'TestRegistry:\ThemisReg\If1' -Force | Out-Null
        New-Item -Path 'TestRegistry:\ThemisReg\If2' -Force | Out-Null
        New-Item -Path 'TestRegistry:\ThemisReg\Other' -Force | Out-Null
        New-ItemProperty -Path 'TestRegistry:\ThemisReg\If1' -Name 'Mode' -Value 2 -PropertyType DWord | Out-Null
        New-ItemProperty -Path 'TestRegistry:\ThemisReg\If2' -Name 'Mode' -Value 0 -PropertyType DWord | Out-Null
    }

    It 'checks and fixes every key that matches a * in the last segment' {
        $rule = @{ ID = 'W'; Name = 'all'; Path = 'TestRegistry:\ThemisReg\If*'; ValueName = 'Mode'; Value = 2; Type = 'DWord' }
        (Invoke-ThemisRule -Type Registry -Rule $rule).Status | Should -Be 'Non-Compliant'
        $r = Invoke-ThemisRule -Type Registry -Rule $rule -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        @($r.Previous).Count | Should -Be 1
        (Get-ItemProperty 'TestRegistry:\ThemisReg\If2').Mode | Should -Be 2
        (Get-ItemProperty 'TestRegistry:\ThemisReg\Other').PSObject.Properties.Name | Should -Not -Contain 'Mode'
    }

    It 'is NotApplicable when no key matches the pattern' {
        (Invoke-ThemisRule -Type Registry -Rule @{ ID = 'W'; Name = 'none'; Path = 'TestRegistry:\ThemisReg\Nope*'; ValueName = 'Mode'; Value = 1; Type = 'DWord' }).Status | Should -Be 'NotApplicable'
    }

    It 'accepts any value of an In list and writes WriteValue' {
        $rule = @{ ID = 'I'; Name = 'in'; Path = 'TestRegistry:\ThemisReg\If2'; ValueName = 'Mode'; Value = @(1, 2); Comparison = 'In'; WriteValue = 2; Type = 'DWord' }
        (Invoke-ThemisRule -Type Registry -Rule $rule).Status | Should -Be 'Non-Compliant'
        (Invoke-ThemisRule -Type Registry -Rule $rule -Mode Enforce).Status | Should -Be 'Fixed'
        (Get-ItemProperty 'TestRegistry:\ThemisReg\If2').Mode | Should -Be 2
        $other = $rule.Clone(); $other.Path = 'TestRegistry:\ThemisReg\If1'
        (Invoke-ThemisRule -Type Registry -Rule $other).Status | Should -Be 'Compliant'
    }

    It 'compares DWORD values as unsigned numbers' {
        New-ItemProperty -Path 'TestRegistry:\ThemisReg\Other' -Name 'Big' -Value ([int]-1) -PropertyType DWord | Out-Null
        $r = Invoke-ThemisRule -Type Registry -Rule @{ ID = 'U'; Name = 'big'; Path = 'TestRegistry:\ThemisReg\Other'; ValueName = 'Big'; Value = 4294967295; Type = 'DWord' }
        $r.Status | Should -Be 'Compliant'
        $r.Actual | Should -Be 4294967295
    }

    It 'removes a value only when it has MatchValue' {
        New-ItemProperty -Path 'TestRegistry:\ThemisReg\Other' -Name 'Debugger' -Value 'systray.exe' -PropertyType String | Out-Null
        New-ItemProperty -Path 'TestRegistry:\ThemisReg\If1' -Name 'Debugger' -Value 'vsjitdebugger.exe' -PropertyType String | Out-Null
        $rule = @{ ID = 'M'; Name = 'hijack'; Path = 'TestRegistry:\ThemisReg\*'; ValueName = 'Debugger'; Ensure = 'Absent'; MatchValue = 'systray.exe' }
        $r = Invoke-ThemisRule -Type Registry -Rule $rule -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        (Get-ItemProperty 'TestRegistry:\ThemisReg\Other').PSObject.Properties.Name | Should -Not -Contain 'Debugger'
        (Get-ItemProperty 'TestRegistry:\ThemisReg\If1').Debugger | Should -Be 'vsjitdebugger.exe'
    }

    It 'removes the key it created when the change is undone' {
        $rule = @{ ID = 'K'; Name = 'new key'; Path = 'TestRegistry:\ThemisReg\Created'; ValueName = 'V'; Value = 1; Type = 'DWord' }
        $r = Invoke-ThemisRule -Type Registry -Rule $rule -Mode Enforce
        'TestRegistry:\ThemisReg\Created' | Should -Exist
        foreach ($previous in $r.Previous) { $null = Invoke-ThemisRule -Type Registry -Rule $previous -Mode Enforce }
        'TestRegistry:\ThemisReg\Created' | Should -Not -Exist
    }
}

Describe 'Service rules with AllowStricter' {
    BeforeEach {
        $script:svc = [pscustomobject]@{ Name = 'ThemisFake'; Status = 'Stopped'; StartType = 'Disabled' }
        $script:svc | Add-Member -MemberType ScriptMethod -Name Refresh -Value { }
        Mock -ModuleName ThemisRules Get-Service { $script:svc }
    }

    It 'accepts a stricter startup type' {
        $r = Invoke-ThemisRule -Type Service -Rule @{ ID = 'S'; Name = 'ThemisFake'; StartupType = 'Manual'; AllowStricter = $true }
        $r.Status | Should -Be 'Compliant'
        $r.Data.StartType | Should -Be 'Disabled'
    }

    It 'requires the exact type without it' {
        (Invoke-ThemisRule -Type Service -Rule @{ ID = 'S'; Name = 'ThemisFake'; StartupType = 'Manual' }).Status | Should -Be 'Non-Compliant'
    }

    It 'stops a running service when it disables it' {
        $script:svc.Status = 'Running'; $script:svc.StartType = 'Manual'
        Mock -ModuleName ThemisRules Set-Service { $script:svc.StartType = $StartupType }
        Mock -ModuleName ThemisRules Stop-Service { $script:svc.Status = 'Stopped' }
        $r = Invoke-ThemisRule -Type Service -Rule @{ ID = 'S'; Name = 'ThemisFake'; StartupType = 'Disabled' } -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        $script:svc.Status | Should -Be 'Stopped'
        $r.Previous[0].State | Should -Be 'Running'
        $r.Previous[0].StartupType | Should -Be 'Manual'
    }
}

Describe 'Feature provider' {
    BeforeEach {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        Mock -ModuleName ThemisRules Get-Command { [pscustomobject]@{ Name = 'Get-WindowsOptionalFeature' } } -ParameterFilter { $Name -eq 'Get-WindowsOptionalFeature' }
        $script:feature = 'Enabled'
        Mock -ModuleName ThemisRules Get-ThemisOptionalFeature { $script:feature }
        Mock -ModuleName ThemisRules Set-ThemisOptionalFeature { $script:feature = $State }
    }

    It 'disables a feature and records how to enable it again' {
        $r = Invoke-ThemisRule -Type Feature -Rule @{ ID = 'F'; Name = 'SMB1'; Feature = 'SMB1Protocol'; State = 'Disabled' } -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        $r.Previous[0].State | Should -Be 'Enabled'
    }

    It 'is NotApplicable when this Windows does not include the feature' {
        $script:feature = $null
        (Invoke-ThemisRule -Type Feature -Rule @{ ID = 'F'; Name = 'old'; Feature = 'Gone'; State = 'Disabled' }).Status | Should -Be 'NotApplicable'
    }

    It 'needs elevation to read features' {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $false }
        (Invoke-ThemisRule -Type Feature -Rule @{ ID = 'F'; Name = 'SMB1'; Feature = 'SMB1Protocol'; State = 'Disabled' }).Status | Should -Be 'NeedsElevation'
    }
}

Describe 'LocalGroupMember provider' {
    BeforeEach {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        $script:groupMembers = @('S-1-5-21-1-2-3-500')
        Mock -ModuleName ThemisRules Get-ThemisLocalGroupMemberSid { , [string[]]$script:groupMembers }
        Mock -ModuleName ThemisRules Set-ThemisLocalGroupMember {
            if ($Ensure -eq 'Present') { $script:groupMembers += $Member }
            else { $script:groupMembers = @($script:groupMembers | Where-Object { $_ -ne $Member }) }
        }
        $script:groupRule = @{ ID = 'G'; Name = 'readers'; Group = 'S-1-5-32-573'; Member = 'S-1-5-21-1-2-3-1001' }
    }

    It 'adds the account and records how to remove it again' {
        $r = Invoke-ThemisRule -Type LocalGroupMember -Rule $script:groupRule -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        $script:groupMembers | Should -Contain 'S-1-5-21-1-2-3-1001'
        $r.Previous[0].Ensure | Should -Be 'Absent'
        $null = Invoke-ThemisRule -Type LocalGroupMember -Rule $r.Previous[0] -Mode Enforce
        $script:groupMembers | Should -Not -Contain 'S-1-5-21-1-2-3-1001'
    }

    It 'reads membership without elevation, but needs it to change it' {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $false }
        (Invoke-ThemisRule -Type LocalGroupMember -Rule $script:groupRule).Status | Should -Be 'Non-Compliant'
        (Invoke-ThemisRule -Type LocalGroupMember -Rule $script:groupRule -Mode Enforce).Status | Should -Be 'NeedsElevation'
        Should -Invoke -ModuleName ThemisRules Set-ThemisLocalGroupMember -Times 0
    }

    It 'is Compliant for Absent when the account is not a member, and NotApplicable without the group' {
        $absent = $script:groupRule.Clone(); $absent.Ensure = 'Absent'
        (Invoke-ThemisRule -Type LocalGroupMember -Rule $absent).Status | Should -Be 'Compliant'
        Mock -ModuleName ThemisRules Get-ThemisLocalGroupMemberSid { $null }
        (Invoke-ThemisRule -Type LocalGroupMember -Rule $script:groupRule).Status | Should -Be 'NotApplicable'
    }

    It 'refuses names instead of SIDs' {
        $byName = $script:groupRule.Clone(); $byName.Group = 'Event Log Readers'
        (Invoke-ThemisRule -Type LocalGroupMember -Rule $byName).Status | Should -Be 'Error'
    }
}

Describe 'LocalGroupMember on this machine' -Skip:(-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) {
    It 'reads real local groups by SID' {
        $members = InModuleScope ThemisRules { Get-ThemisLocalGroupMemberSid -Group 'S-1-5-32-544' }
        $members | Should -Not -BeNullOrEmpty
        InModuleScope ThemisRules { Get-ThemisLocalGroupMemberSid -Group 'S-1-5-32-999999' } | Should -BeNullOrEmpty
    }
}

Describe 'SecureFolder provider' -Skip:(-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) {
    It 'creates the folder with the permissions and removes it again on restore' {
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $path = Join-Path $TestDrive 'secure'
        $rule = @{ ID = 'SF'; Name = 'folder'; Path = $path; Sddl = "D:PAI(A;OICI;FA;;;$me)(A;OICI;FA;;;SY)" }
        $r = Invoke-ThemisRule -Type SecureFolder -Rule $rule -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        (Invoke-ThemisRule -Type SecureFolder -Rule $rule).Status | Should -Be 'Compliant'
        $r.Previous[0].Ensure | Should -Be 'Absent'
        $null = Invoke-ThemisRule -Type SecureFolder -Rule $r.Previous[0] -Mode Enforce
        $path | Should -Not -Exist
    }

    It 'never removes a folder that has files' {
        $path = Join-Path $TestDrive 'withfiles'
        New-Item -ItemType Directory -Path $path | Out-Null
        Set-Content -Path (Join-Path $path 'keep.txt') -Value 'data'
        $r = Invoke-ThemisRule -Type SecureFolder -Rule @{ ID = 'SF'; Name = 'folder'; Path = $path; Ensure = 'Absent' } -Mode Enforce
        $r.Status | Should -Be 'EnforceFailed'
        Join-Path $path 'keep.txt' | Should -Exist
    }

    It 'refuses relative paths' {
        (Invoke-ThemisRule -Type SecureFolder -Rule @{ ID = 'SF'; Name = 'x'; Path = '..\x'; Sddl = 'D:(A;;FA;;;SY)' }).Status | Should -Be 'Error'
    }
}

Describe 'Check provider' {
    It 'is Compliant, Manual or Unknown depending on the fact, and never changes anything' {
        $rule = @{ ID = 'CK'; Name = 'Secure Boot'; Fact = 'SecureBootOn'; Expected = $true; Action = 'Turn on Secure Boot in the firmware' }
        (Invoke-ThemisRule -Type Check -Rule $rule -Facts @{ SecureBootOn = $true }).Status | Should -Be 'Compliant'
        $manual = Invoke-ThemisRule -Type Check -Rule $rule -Mode Enforce -Facts @{ SecureBootOn = $false }
        $manual.Status | Should -Be 'Manual'
        $manual.Reason | Should -Match 'Turn on Secure Boot'
        @($manual.Previous).Count | Should -Be 0
        (Invoke-ThemisRule -Type Check -Rule $rule).Status | Should -Be 'Unknown'
    }
}

Describe 'Firewall restore of NotConfigured' {
    It 'records the local value, so a setting that was not configured goes back to that' {
        $script:local = 'NotConfigured'; $script:active = 'Allow'
        Mock -ModuleName ThemisRules Get-Command { [pscustomobject]@{ Name = 'Get-NetFirewallProfile' } } -ParameterFilter { $Name -eq 'Get-NetFirewallProfile' }
        Mock -ModuleName ThemisRules Get-ThemisFirewallProfile { if ($Local) { [pscustomobject]@{ DefaultInboundAction = $script:local } } else { [pscustomobject]@{ DefaultInboundAction = $script:active } } }
        Mock -ModuleName ThemisRules Set-ThemisFirewallProfile { $script:local = $Value; $script:active = if ($Value -eq 'NotConfigured') { 'Block' } else { $Value } }
        $r = Invoke-ThemisRule -Type FirewallProfile -Rule @{ ID = 'FW'; Name = 'in'; Profile = 'Public'; Setting = 'DefaultInboundAction'; Value = 'Block' } -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        $r.Previous[0].Value | Should -Be 'NotConfigured'
        (Invoke-ThemisRule -Type FirewallProfile -Rule $r.Previous[0] -Mode Enforce).Status | Should -Be 'Fixed'
        $script:local | Should -Be 'NotConfigured'
    }
}

Describe 'Invoke-ThemisRule -KeepReadCache' {
    It 'uses what an earlier call read instead of reading it again' {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        $guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'
        # A value no real machine reports for this rule: only the cache can produce it.
        InModuleScope ThemisRules -Parameters @{ Guid = $guid } { param($Guid) $script:ThemisRunCache = @{ AuditPolicy = @{ $Guid = 3 } } }
        $r = Invoke-ThemisRule -Type AuditPolicy -Rule @{ ID = 'A'; Name = 'logon'; Subcategory = $guid; Setting = 'SuccessAndFailure'; Exact = $true } -KeepReadCache
        $r.Actual | Should -Be 'SuccessAndFailure'
        InModuleScope ThemisRules { $script:ThemisRunCache.ContainsKey('AuditPolicy') } | Should -BeTrue
    }
}
