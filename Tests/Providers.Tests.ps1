BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../ThemisRules.psd1') -Force

    function New-Rule([hashtable]$Properties) { [pscustomobject]$Properties }
}

Describe 'Value comparison' {
    It '<Comparison> <Actual> against <Value>/<Min>-<Max> is <Expected>' -TestCases @(
        @{ Comparison = 'Equal'; Actual = 5; Value = 5; Min = $null; Max = $null; Expected = $true }
        @{ Comparison = 'Equal'; Actual = 'Block'; Value = 'block'; Min = $null; Max = $null; Expected = $true }
        @{ Comparison = 'Equal'; Actual = 4; Value = 5; Min = $null; Max = $null; Expected = $false }
        @{ Comparison = 'AtLeast'; Actual = 24; Value = 14; Min = $null; Max = $null; Expected = $true }
        @{ Comparison = 'AtLeast'; Actual = 8; Value = 14; Min = $null; Max = $null; Expected = $false }
        @{ Comparison = 'AtMost'; Actual = 0; Value = 1; Min = $null; Max = $null; Expected = $true }
        @{ Comparison = 'Between'; Actual = 0; Value = 10; Min = 1; Max = 10; Expected = $false }
        @{ Comparison = 'Between'; Actual = 5; Value = 10; Min = 1; Max = 10; Expected = $true }
        @{ Comparison = 'AtLeast'; Actual = $null; Value = 1; Min = $null; Max = $null; Expected = $false }
    ) {
        $rule = [pscustomobject]@{ Comparison = $Comparison; Value = $Value; Min = $Min; Max = $Max }
        (InModuleScope ThemisRules -Parameters @{ Rule = $rule; Actual = $Actual } { param($Rule, $Actual) Test-ThemisValue -Actual $Actual -Rule $Rule }).Match |
            Should -Be $Expected
    }
}

Describe 'AuditPolicy provider' {
    BeforeAll {
        $logon = '{0CCE9215-69AE-11D9-BED3-505054503030}'
    }
    BeforeEach {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        Mock -ModuleName ThemisRules Set-ThemisAuditPolicySetting { }
    }

    It 'treats auditing more than required as compliant' {
        Mock -ModuleName ThemisRules Get-ThemisAuditPolicySetting { @{ '{0CCE9215-69AE-11D9-BED3-505054503030}' = 3 } }
        $result = InModuleScope ThemisRules -Parameters @{ Logon = $logon } { param($Logon) Invoke-ThemisAuditPolicyRule -Rule ([pscustomobject]@{ Subcategory = $Logon; Setting = 'Success' }) -Mode Audit }
        $result.Status | Should -Be 'Compliant'
        $result.Actual | Should -Be 'SuccessAndFailure'
    }

    It 'reports a missing flag as non-compliant without changing anything in Audit mode' {
        Mock -ModuleName ThemisRules Get-ThemisAuditPolicySetting { @{ '{0CCE9215-69AE-11D9-BED3-505054503030}' = 1 } }
        $result = InModuleScope ThemisRules -Parameters @{ Logon = $logon } { param($Logon) Invoke-ThemisAuditPolicyRule -Rule ([pscustomobject]@{ Subcategory = $Logon; Setting = 'SuccessAndFailure' }) -Mode Audit }
        $result.Status | Should -Be 'Non-Compliant'
        Should -Invoke -ModuleName ThemisRules Set-ThemisAuditPolicySetting -Times 0 -Exactly
    }

    It 'adds the missing flag and keeps the existing one in Enforce mode' {
        $script:state = 2
        Mock -ModuleName ThemisRules Get-ThemisAuditPolicySetting { @{ '{0CCE9215-69AE-11D9-BED3-505054503030}' = $script:state } }
        Mock -ModuleName ThemisRules Set-ThemisAuditPolicySetting { $script:state = ([int]$Success) + 2 * ([int]$Failure) }
        $result = InModuleScope ThemisRules -Parameters @{ Logon = $logon } { param($Logon) Invoke-ThemisAuditPolicyRule -Rule ([pscustomobject]@{ Subcategory = $Logon; Setting = 'Success' }) -Mode Enforce }
        $result.Status | Should -Be 'Fixed'
        Should -Invoke -ModuleName ThemisRules Set-ThemisAuditPolicySetting -ParameterFilter { $Success -and $Failure }
    }

    It 'rejects a subcategory that is not a GUID' {
        $result = InModuleScope ThemisRules { Invoke-ThemisAuditPolicyRule -Rule ([pscustomobject]@{ Subcategory = 'Logon'; Setting = 'Success' }) -Mode Enforce }
        $result.Status | Should -Be 'Error'
        Should -Invoke -ModuleName ThemisRules Set-ThemisAuditPolicySetting -Times 0 -Exactly
    }

    It 'reports that elevation is needed' {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $false }
        $result = InModuleScope ThemisRules -Parameters @{ Logon = $logon } { param($Logon) Invoke-ThemisAuditPolicyRule -Rule ([pscustomobject]@{ Subcategory = $Logon; Setting = 'Success' }) -Mode Audit }
        $result.Status | Should -Be 'Error'
        $result.Reason | Should -Match 'elevated'
    }
}

Describe 'SecurityPolicy provider' {
    BeforeEach {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        $script:policy = @{ MinimumPasswordLength = '8'; LockoutBadCount = '0' }
        Mock -ModuleName ThemisRules Get-ThemisSecurityPolicy { $script:policy }
        Mock -ModuleName ThemisRules Set-ThemisSecurityPolicy { foreach ($k in $Settings.Keys) { $script:policy[$k] = "$($Settings[$k])" } }
    }

    It 'compares with AtLeast' {
        $result = InModuleScope ThemisRules { Invoke-ThemisSecurityPolicyRule -Rule ([pscustomobject]@{ Key = 'MinimumPasswordLength'; Value = 14; Comparison = 'AtLeast' }) -Mode Audit }
        $result.Status | Should -Be 'Non-Compliant'
        $result.Reason | Should -Match '14 or more'
    }

    It 'treats 0 as outside Between 1 and 10, and fixes it in Enforce mode' {
        $result = InModuleScope ThemisRules { Invoke-ThemisSecurityPolicyRule -Rule ([pscustomobject]@{ Key = 'LockoutBadCount'; Value = 10; Comparison = 'Between'; Min = 1; Max = 10 }) -Mode Enforce }
        $result.Status | Should -Be 'Fixed'
        $script:policy.LockoutBadCount | Should -Be '10'
    }

    It 'refuses keys outside the supported list' {
        $result = InModuleScope ThemisRules { Invoke-ThemisSecurityPolicyRule -Rule ([pscustomobject]@{ Key = "NewAdministratorName"; Value = 1 }) -Mode Enforce }
        $result.Status | Should -Be 'Error'
        Should -Invoke -ModuleName ThemisRules Set-ThemisSecurityPolicy -Times 0 -Exactly
    }

    It 'refuses values that are not whole numbers' {
        $result = InModuleScope ThemisRules { Invoke-ThemisSecurityPolicyRule -Rule ([pscustomobject]@{ Key = 'MinimumPasswordLength'; Value = "14`n[Privilege Rights]" }) -Mode Enforce }
        $result.Status | Should -Be 'Error'
        Should -Invoke -ModuleName ThemisRules Set-ThemisSecurityPolicy -Times 0 -Exactly
    }

    It 'reports EnforceFailed when the value does not change (domain policy)' {
        Mock -ModuleName ThemisRules Set-ThemisSecurityPolicy { }
        $result = InModuleScope ThemisRules { Invoke-ThemisSecurityPolicyRule -Rule ([pscustomobject]@{ Key = 'MinimumPasswordLength'; Value = 14; Comparison = 'AtLeast' }) -Mode Enforce }
        $result.Status | Should -Be 'EnforceFailed'
    }
}

Describe 'FirewallProfile provider' {
    BeforeEach {
        $script:fw = @{ Enabled = 'False'; DefaultInboundAction = 'Allow'; LogMaxSizeKilobytes = 4096 }
        Mock -ModuleName ThemisRules Get-Command { [pscustomobject]@{ Name = 'Get-NetFirewallProfile' } } -ParameterFilter { $Name -eq 'Get-NetFirewallProfile' }
        Mock -ModuleName ThemisRules Get-ThemisFirewallProfile { [pscustomobject]$script:fw }
        Mock -ModuleName ThemisRules Set-ThemisFirewallProfile { $script:fw[$Setting] = $Value }
    }

    It 'enables a disabled profile in Enforce mode' {
        $result = InModuleScope ThemisRules { Invoke-ThemisFirewallProfileRule -Rule ([pscustomobject]@{ Profile = 'Public'; Setting = 'Enabled'; Value = 'True' }) -Mode Enforce }
        $result.Status | Should -Be 'Fixed'
        $script:fw.Enabled | Should -Be 'True'
    }

    It 'compares the log size with AtLeast' {
        $result = InModuleScope ThemisRules { Invoke-ThemisFirewallProfileRule -Rule ([pscustomobject]@{ Profile = 'Domain'; Setting = 'LogMaxSizeKilobytes'; Value = 16384; Comparison = 'AtLeast' }) -Mode Audit }
        $result.Status | Should -Be 'Non-Compliant'
    }

    It 'reports EnforceFailed when Group Policy keeps the old value' {
        Mock -ModuleName ThemisRules Set-ThemisFirewallProfile { }
        $result = InModuleScope ThemisRules { Invoke-ThemisFirewallProfileRule -Rule ([pscustomobject]@{ Profile = 'Private'; Setting = 'DefaultInboundAction'; Value = 'Block' }) -Mode Enforce }
        $result.Status | Should -Be 'EnforceFailed'
    }

    It 'rejects <Case>' -TestCases @(
        @{ Case = 'an unknown profile'; Rule = @{ Profile = 'Home'; Setting = 'Enabled'; Value = 'True' } }
        @{ Case = 'an unknown setting'; Rule = @{ Profile = 'Public'; Setting = 'AllowInboundRules'; Value = 'True' } }
        @{ Case = 'an invalid value'; Rule = @{ Profile = 'Public'; Setting = 'DefaultInboundAction'; Value = 'Maybe' } }
    ) {
        $result = InModuleScope ThemisRules -Parameters @{ Rule = [pscustomobject]$Rule } { param($Rule) Invoke-ThemisFirewallProfileRule -Rule $Rule -Mode Enforce }
        $result.Status | Should -Be 'Error'
        Should -Invoke -ModuleName ThemisRules Set-ThemisFirewallProfile -Times 0 -Exactly
    }
}

Describe 'Registry provider' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    BeforeEach {
        New-Item -Path 'TestRegistry:\ThemisProviders' -Force | Out-Null
        New-ItemProperty -Path 'TestRegistry:\ThemisProviders' -Name 'Size' -Value 4096 -PropertyType DWord | Out-Null
    }

    It 'treats a missing value as compliant when its Windows default meets the rule' {
        $rule = [pscustomobject]@{ Path = 'TestRegistry:\ThemisProviders'; ValueName = 'Absent'; Value = 0; Type = 'DWord'; Default = 0 }
        $result = InModuleScope ThemisRules -Parameters @{ Rule = $rule } { param($Rule) Invoke-ThemisRegistryRule -Rule $Rule -Mode Audit }
        $result.Status | Should -Be 'Compliant'
        $result.Actual | Should -Match 'default'
    }

    It 'still reports a missing value when the default does not meet the rule' {
        $rule = [pscustomobject]@{ Path = 'TestRegistry:\ThemisProviders'; ValueName = 'Absent'; Value = 5; Type = 'DWord'; Default = 3 }
        $result = InModuleScope ThemisRules -Parameters @{ Rule = $rule } { param($Rule) Invoke-ThemisRegistryRule -Rule $Rule -Mode Audit }
        $result.Status | Should -Be 'MissingValue'
    }

    It 'compares with AtLeast and writes Value in Enforce mode' {
        $rule = [pscustomobject]@{ Path = 'TestRegistry:\ThemisProviders'; ValueName = 'Size'; Value = 32768; Type = 'DWord'; Comparison = 'AtLeast' }
        $result = InModuleScope ThemisRules -Parameters @{ Rule = $rule } { param($Rule) Invoke-ThemisRegistryRule -Rule $Rule -Mode Enforce }
        $result.Status | Should -Be 'Fixed'
        (Get-ItemProperty 'TestRegistry:\ThemisProviders').Size | Should -Be 32768
    }
}

Describe 'Service provider' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    It 'treats a service that is not installed as compliant when it should be disabled' {
        $rule = [pscustomobject]@{ Name = "ThemisMissing$(Get-Random)"; State = 'Stopped'; StartupType = 'Disabled' }
        $result = InModuleScope ThemisRules -Parameters @{ Rule = $rule } { param($Rule) Invoke-ThemisServiceRule -Rule $Rule -Mode Audit }
        $result.Status | Should -Be 'Compliant'
    }

    It 'reports a missing service that should be running' {
        $rule = [pscustomobject]@{ Name = "ThemisMissing$(Get-Random)"; State = 'Running' }
        $result = InModuleScope ThemisRules -Parameters @{ Rule = $rule } { param($Rule) Invoke-ThemisServiceRule -Rule $Rule -Mode Audit }
        $result.Status | Should -Be 'MissingService'
    }
}
