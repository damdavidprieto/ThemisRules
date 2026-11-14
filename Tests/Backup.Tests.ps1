BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../ThemisRules.psd1') -Force

    function New-TestPolicy([string]$Path, [hashtable]$Content) {
        $Content | ConvertTo-Json -Depth 6 | Set-Content -Path $Path
        $Path
    }
}

Describe 'UserRights provider' {
    BeforeEach {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        $script:rights = @{ SeDebugPrivilege = @('S-1-5-32-544', 'S-1-5-32-551'); SeDenyNetworkLogonRight = @() }
        Mock -ModuleName ThemisRules Get-ThemisUserRight { $script:rights }
        Mock -ModuleName ThemisRules Set-ThemisUserRight { $script:rights[$Right] = @($Principals) }
    }

    It 'Equal: reports extra principals and assigns exactly the list in Enforce mode' {
        $rule = [pscustomobject]@{ Right = 'SeDebugPrivilege'; Principals = @('S-1-5-32-544') }
        $result = InModuleScope ThemisRules -Parameters @{ Rule = $rule } { param($Rule) Invoke-ThemisUserRightsRule -Rule $Rule -Mode Enforce }
        $result.Status | Should -Be 'Fixed'
        $script:rights.SeDebugPrivilege | Should -Be @('S-1-5-32-544')
        $result.Previous.Principals | Should -Be @('S-1-5-32-544', 'S-1-5-32-551')
    }

    It 'Includes: adds the missing principal and keeps the others' {
        $script:rights.SeDenyNetworkLogonRight = @('S-1-5-113')
        $rule = [pscustomobject]@{ Right = 'SeDenyNetworkLogonRight'; Principals = @('S-1-5-32-546'); Comparison = 'Includes' }
        $result = InModuleScope ThemisRules -Parameters @{ Rule = $rule } { param($Rule) Invoke-ThemisUserRightsRule -Rule $Rule -Mode Enforce }
        $result.Status | Should -Be 'Fixed'
        $script:rights.SeDenyNetworkLogonRight | Should -Be @('S-1-5-113', 'S-1-5-32-546')
    }

    It 'Excludes: removes only the listed principal' {
        $rule = [pscustomobject]@{ Right = 'SeDebugPrivilege'; Principals = @('S-1-5-32-551'); Comparison = 'Excludes' }
        $result = InModuleScope ThemisRules -Parameters @{ Rule = $rule } { param($Rule) Invoke-ThemisUserRightsRule -Rule $Rule -Mode Enforce }
        $result.Status | Should -Be 'Fixed'
        $script:rights.SeDebugPrivilege | Should -Be @('S-1-5-32-544')
    }

    It 'treats a right nobody holds as compliant with an empty Equal list' {
        $rule = [pscustomobject]@{ Right = 'SeTcbPrivilege'; Principals = @() }
        $result = InModuleScope ThemisRules -Parameters @{ Rule = $rule } { param($Rule) Invoke-ThemisUserRightsRule -Rule $Rule -Mode Audit }
        $result.Status | Should -Be 'Compliant'
    }

    It 'rejects <Case>' -TestCases @(
        @{ Case = 'account names instead of SIDs'; Rule = @{ Right = 'SeDebugPrivilege'; Principals = @('Administrators') } }
        @{ Case = 'a right that is not a constant'; Rule = @{ Right = "SeDebugPrivilege = *S-1-1-0`n[x]"; Principals = @() } }
        @{ Case = 'an unknown comparison'; Rule = @{ Right = 'SeDebugPrivilege'; Principals = @(); Comparison = 'Maybe' } }
    ) {
        $result = InModuleScope ThemisRules -Parameters @{ Rule = [pscustomobject]$Rule } { param($Rule) Invoke-ThemisUserRightsRule -Rule $Rule -Mode Enforce }
        $result.Status | Should -Be 'Error'
        Should -Invoke -ModuleName ThemisRules Set-ThemisUserRight -Times 0 -Exactly
    }
}

Describe 'AuditPolicy Exact (used by backups)' {
    It 'sets exactly the requested setting, removing extra flags' {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        $script:audit = 3
        Mock -ModuleName ThemisRules Get-ThemisAuditPolicySetting { @{ '{0CCE9215-69AE-11D9-BED3-505054503030}' = $script:audit } }
        Mock -ModuleName ThemisRules Set-ThemisAuditPolicySetting { $script:audit = ([int]$Success) + 2 * ([int]$Failure) }
        $rule = [pscustomobject]@{ Subcategory = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Setting = 'Success'; Exact = $true }
        $result = InModuleScope ThemisRules -Parameters @{ Rule = $rule } { param($Rule) Invoke-ThemisAuditPolicyRule -Rule $Rule -Mode Enforce }
        $result.Status | Should -Be 'Fixed'
        $script:audit | Should -Be 1
    }
}

Describe 'Backups and Restore-ThemisBackup' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    BeforeEach {
        New-Item -Path 'TestRegistry:\ThemisBackup' -Force | Out-Null
        New-ItemProperty -Path 'TestRegistry:\ThemisBackup' -Name 'Existing' -Value 7 -PropertyType DWord | Out-Null
        $backups = Join-Path $TestDrive ("backups_" + [guid]::NewGuid().ToString('N'))
        $policy = New-TestPolicy -Path (Join-Path $TestDrive 'backup-policy.json') -Content @{
            Meta          = @{ Name = 'Backup test'; Version = '1.0.0' }
            RegistryRules = @(
                @{ ID = 'B-1'; Name = 'Change existing'; Path = 'TestRegistry:\ThemisBackup'; ValueName = 'Existing'; Value = 1; Type = 'DWord' }
                @{ ID = 'B-2'; Name = 'Create new'; Path = 'TestRegistry:\ThemisBackup'; ValueName = 'Created'; Value = 'x'; Type = 'String' }
            )
        }
    }

    It 'saves the previous values and adds the backup path to the results' {
        $results = Invoke-ThemisPolicy -PolicyPath $policy -Mode Enforce -BackupPath $backups
        $results.Status | Should -Be @('Fixed', 'Fixed')
        $results[0].Backup | Should -Exist
        $backup = Get-Content $results[0].Backup -Raw | ConvertFrom-Json
        ($backup.RegistryRules | Where-Object ID -EQ 'B-1').Value | Should -Be 7
        ($backup.RegistryRules | Where-Object ID -EQ 'B-2').Ensure | Should -Be 'Absent'
    }

    It 'Restore-ThemisBackup puts the old value back and removes the value Enforce created' {
        $results = Invoke-ThemisPolicy -PolicyPath $policy -Mode Enforce -BackupPath $backups
        Restore-ThemisBackup -Path $results[0].Backup | Out-Null

        $key = Get-ItemProperty 'TestRegistry:\ThemisBackup'
        $key.Existing | Should -Be 7
        $key.PSObject.Properties.Name | Should -Not -Contain 'Created'
    }

    It 'Get-ThemisBackup lists the backups, newest first' {
        Invoke-ThemisPolicy -PolicyPath $policy -Mode Enforce -BackupPath $backups | Out-Null
        $list = @(Get-ThemisBackup -Path $backups)
        $list.Count | Should -Be 1
        $list[0].Policy | Should -Be 'Backup test'
        $list[0].Values | Should -Be 2
    }

    It 'writes no backup with -NoBackup or in Audit mode' {
        Invoke-ThemisPolicy -PolicyPath $policy -Mode Audit -BackupPath $backups | Out-Null
        Invoke-ThemisPolicy -PolicyPath $policy -Mode Enforce -BackupPath $backups -NoBackup | Out-Null
        @(Get-ThemisBackup -Path $backups).Count | Should -Be 0
    }

    It 'writes no backup with -WhatIf' {
        Invoke-ThemisPolicy -PolicyPath $policy -Mode Enforce -BackupPath $backups -WhatIf | Out-Null
        @(Get-ThemisBackup -Path $backups).Count | Should -Be 0
        (Get-ItemProperty 'TestRegistry:\ThemisBackup').Existing | Should -Be 7
    }
}

Describe 'Restore-ThemisBackup -WhatIf' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    It 'audits the backup and changes nothing' {
        New-Item -Path 'TestRegistry:\ThemisRestoreWhatIf' -Force | Out-Null
        New-ItemProperty -Path 'TestRegistry:\ThemisRestoreWhatIf' -Name 'V' -Value 2 -PropertyType DWord | Out-Null
        $backup = Join-Path $TestDrive 'whatif-backup.json'
        @{ Meta = @{ Name = 'Backup before enforcing X'; Version = '1.0.0' }; RegistryRules = @(@{ ID = 'R-1'; Name = 'Restore V'; Path = 'TestRegistry:\ThemisRestoreWhatIf'; ValueName = 'V'; Value = 5; Type = 'DWord' }) } |
            ConvertTo-Json -Depth 5 | Set-Content $backup

        $results = Restore-ThemisBackup -Path $backup -WhatIf
        $results.Status | Should -Be 'Non-Compliant'
        (Get-ItemProperty 'TestRegistry:\ThemisRestoreWhatIf').V | Should -Be 2
    }
}
