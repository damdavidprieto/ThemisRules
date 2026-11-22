BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../ThemisRules.psd1') -Force

    function New-TestPolicy([string]$Path, [hashtable]$Content) {
        $Content | ConvertTo-Json -Depth 6 | Set-Content -Path $Path
        $Path
    }
}

Describe 'Verified and RequiresRestart' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    BeforeEach {
        New-Item -Path 'TestRegistry:\ThemisSafe' -Force | Out-Null
        New-ItemProperty -Path 'TestRegistry:\ThemisSafe' -Name 'Level' -Value 1 -PropertyType DWord -Force | Out-Null
        $script:rule = @{ ID = 'S1'; Name = 'Level'; Path = 'TestRegistry:\ThemisSafe'; ValueName = 'Level'; Value = 2; Type = 'DWord' }
    }

    It 'reads the change back and says it is done, without a restart' {
        $r = Invoke-ThemisRule -Type Registry -Rule $script:rule -Mode Enforce
        $r.Verified | Should -BeTrue
        $r.RequiresRestart | Should -BeFalse
    }

    It 'passes on RequiresRestart from the rule' {
        $rule = $script:rule.Clone(); $rule.RequiresRestart = $true
        (Invoke-ThemisRule -Type Registry -Rule $rule -Mode Enforce).RequiresRestart | Should -BeTrue
    }

    It 'says when the change does not show when read again' {
        Mock -ModuleName ThemisRules Invoke-ThemisEventLogRule {
            if ($Mode -eq 'Enforce') { [ordered]@{ Status = 'Fixed'; IsCompliant = $true; Reason = 'set'; Previous = [ordered]@{ LogName = 'X'; MaxSizeMB = 1 } } }
            else { [ordered]@{ Status = 'Non-Compliant'; IsCompliant = $false; Reason = 'still small' } }
        }
        $r = Invoke-ThemisRule -Type EventLog -Rule @{ ID = 'L'; Name = 'log'; LogName = 'Application'; MaxSizeMB = 64 } -Mode Enforce
        $r.Verified | Should -BeFalse
        $r.Reason | Should -Match 'does not show the change'
    }

    It 'leaves both empty when nothing changed' {
        $r = Invoke-ThemisRule -Type Registry -Rule $script:rule
        $r.Verified | Should -BeNullOrEmpty
        $r.RequiresRestart | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-ThemisPolicy -RollbackOnFailure' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    It 'undoes the changes of the run when a later rule fails, and stops' {
        New-Item -Path 'TestRegistry:\ThemisAtomic' -Force | Out-Null
        New-ItemProperty -Path 'TestRegistry:\ThemisAtomic' -Name 'A' -Value 1 -PropertyType DWord -Force | Out-Null
        Mock -ModuleName ThemisRules Invoke-ThemisEventLogRule {
            if ($Mode -eq 'Enforce') { [ordered]@{ Status = 'EnforceFailed'; IsCompliant = $false; Reason = 'could not' } }
            else { [ordered]@{ Status = 'Non-Compliant'; IsCompliant = $false; Reason = 'small' } }
        }
        $policy = New-TestPolicy -Path (Join-Path $TestDrive 'atomic.json') -Content @{
            Meta          = @{ Name = 'atomic' }
            RegistryRules = @(@{ ID = 'A1'; Name = 'A'; Path = 'TestRegistry:\ThemisAtomic'; ValueName = 'A'; Value = 2; Type = 'DWord' })
            EventLogRules = @(@{ ID = 'E1'; Name = 'log'; LogName = 'Application'; MaxSizeMB = 64 })
        }
        $results = @(Invoke-ThemisPolicy -PolicyPath $policy -Mode Enforce -BackupPath (Join-Path $TestDrive 'bk-atomic') -RollbackOnFailure -Confirm:$false -WarningAction SilentlyContinue)
        (Get-ItemProperty 'TestRegistry:\ThemisAtomic').A | Should -Be 1
        ($results | Where-Object ID -EQ 'A1').RolledBack | Should -BeTrue
        ($results | Where-Object ID -EQ 'E1').Status | Should -Be 'EnforceFailed'
    }
}

Describe 'Test-ThemisPolicy and -Strict' {
    It 'finds unknown fields with a hint, missing required fields and sections without a provider' {
        $policy = New-TestPolicy -Path (Join-Path $TestDrive 'typo.json') -Content @{
            Meta          = @{ Name = 'typo' }
            RegistryRules = @(@{ ID = 'T1'; Name = 'x'; Path = 'HKCU:\Software\X'; ValueName = 'V'; Vaule = 1 }, @{ ID = 'T2'; Name = 'y'; Path = 'HKCU:\Software\X' })
            NopeRules     = @(@{ ID = 'N1' })
        }
        $problems = @(Test-ThemisPolicy -Path $policy)
        ($problems | Where-Object ID -EQ 'T1').Problem | Should -Match 'Unknown field Vaule \(did you mean Value\?\)'
        ($problems | Where-Object ID -EQ 'T2').Problem | Should -Match 'ValueName is missing'
        ($problems | Where-Object Section -EQ 'NopeRules').Problem | Should -Match 'No provider'
    }

    It 'refuses to run a policy with problems under -Strict' {
        $policy = New-TestPolicy -Path (Join-Path $TestDrive 'strict.json') -Content @{
            Meta          = @{ Name = 'strict' }
            RegistryRules = @(@{ ID = 'T1'; Name = 'x'; Path = 'HKCU:\Software\X'; ValueName = 'V'; Vaule = 1 })
        }
        $r = Invoke-ThemisPolicy -PolicyPath $policy -Strict -ErrorAction SilentlyContinue -ErrorVariable err
        $r | Should -BeNullOrEmpty
        "$err" | Should -Match 'Unknown field Vaule'
    }

    It 'accepts the shipped baselines' {
        foreach ($b in Get-ThemisBaseline) { @(Test-ThemisPolicy -Path $b.Path) | Should -BeNullOrEmpty -Because $b.Name }
    }
}

Describe 'Backup content hash' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    It 'refuses to restore a backup that was edited after it was saved' {
        New-Item -Path 'TestRegistry:\ThemisHash' -Force | Out-Null
        New-ItemProperty -Path 'TestRegistry:\ThemisHash' -Name 'H' -Value 1 -PropertyType DWord -Force | Out-Null
        $policy = New-TestPolicy -Path (Join-Path $TestDrive 'hash.json') -Content @{
            Meta          = @{ Name = 'hash' }
            RegistryRules = @(@{ ID = 'H1'; Name = 'H'; Path = 'TestRegistry:\ThemisHash'; ValueName = 'H'; Value = 2; Type = 'DWord' })
        }
        $results = @(Invoke-ThemisPolicy -PolicyPath $policy -Mode Enforce -BackupPath (Join-Path $TestDrive 'bk-hash') -Confirm:$false)
        $file = $results[0].Backup
        (Get-Content $file -Raw | ConvertFrom-Json).Meta.ContentHash | Should -Match '^[0-9a-f]{64}$'
        $text = (Get-Content $file -Raw) -replace '"Value":\s*1', '"Value":  7'
        Set-Content -Path $file -Value $text
        Restore-ThemisBackup -Path $file -Confirm:$false -ErrorAction SilentlyContinue -ErrorVariable err | Out-Null
        "$err" | Should -Match 'changed after Themis saved it'
        (Get-ItemProperty 'TestRegistry:\ThemisHash').H | Should -Be 2
    }
}

Describe 'Compare-ThemisResult' {
    It 'reports drifted, fixed, added and removed rules' {
        $mk = { param($id, $ok) [pscustomobject]@{ ID = $id; Type = 'Registry'; Name = $id; Status = $(if ($ok) { 'Compliant' } else { 'Non-Compliant' }); IsCompliant = $ok; Reason = '' } }
        $before = @((& $mk 'A' $true), (& $mk 'B' $false), (& $mk 'C' $true), (& $mk 'D' $true))
        $after = @((& $mk 'A' $false), (& $mk 'B' $true), (& $mk 'C' $true), (& $mk 'E' $true))
        $c = @(Compare-ThemisResult -Reference $before -Difference $after)
        ($c | Where-Object ID -EQ 'A').Change | Should -Be 'Drifted'
        ($c | Where-Object ID -EQ 'B').Change | Should -Be 'Fixed'
        ($c | Where-Object ID -EQ 'E').Change | Should -Be 'Added'
        ($c | Where-Object ID -EQ 'D').Change | Should -Be 'Removed'
        $c.ID | Should -Not -Contain 'C'
    }
}
