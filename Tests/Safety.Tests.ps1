BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../ThemisRules.psd1') -Force

    function New-TestPolicy([string]$Path, [hashtable]$Content) {
        $Content | ConvertTo-Json -Depth 6 | Set-Content -Path $Path
        $Path
    }
}

Describe 'Windows tools are called by full path' {
    It 'never calls auditpol, secedit or sc by bare name' {
        # By bare name PowerShell searches the current folder and the PATH first; in an elevated
        # session a program planted there would run as administrator.
        $root = Join-Path $PSScriptRoot '..'
        $bare = @(Get-ChildItem (Join-Path $root 'Core'), (Join-Path $root 'Providers'), (Join-Path $root 'Public') -Filter '*.ps1' |
                Select-String -Pattern '&\s*(auditpol|secedit|sc|netsh|reg)(\.exe)?\s' |
                ForEach-Object { "$($_.Filename):$($_.LineNumber)" })
        $bare | Should -BeNullOrEmpty
    }

    It 'resolves tools to the System32 folder' -Skip:(-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) {
        $path = InModuleScope ThemisRules { Get-ThemisSystemTool -Name 'auditpol.exe' }
        $path | Should -Be (Join-Path ([Environment]::GetFolderPath('System')) 'auditpol.exe')
    }
}

Describe 'MacroLevel filter' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    BeforeAll {
        New-Item -Path 'TestRegistry:\ThemisLevels' -Force | Out-Null
        $policy = New-TestPolicy -Path (Join-Path $TestDrive 'levels.json') -Content @{
            Meta          = @{ Name = 'Levels'; Version = '1.0.0' }
            RegistryRules = @(
                @{ ID = 'LV-1'; MacroLevel = 'L1'; Name = 'Level 1'; Path = 'TestRegistry:\ThemisLevels'; ValueName = 'A'; Value = 1; Type = 'DWord' }
                @{ ID = 'LV-0'; Name = 'No level'; Path = 'TestRegistry:\ThemisLevels'; ValueName = 'B'; Value = 1; Type = 'DWord' }
                @{ ID = 'LV-3'; MacroLevel = 'L3'; Name = 'Level 3'; Path = 'TestRegistry:\ThemisLevels'; ValueName = 'C'; Value = 1; Type = 'DWord' }
                @{ ID = 'LV-X'; MacroLevel = 'L9'; Name = 'Invalid level'; Path = 'TestRegistry:\ThemisLevels'; ValueName = 'D'; Value = 1; Type = 'DWord' }
            )
        }
    }

    It 'always evaluates rules without a level, as the help says' {
        $ids = (Invoke-ThemisPolicy -PolicyPath $policy -MacroLevel L1 -WarningAction SilentlyContinue).ID
        $ids | Should -Contain 'LV-0'
        $ids | Should -Contain 'LV-1'
        $ids | Should -Not -Contain 'LV-3'
    }

    It 'skips a rule with an invalid level, with a warning' {
        $results = Invoke-ThemisPolicy -PolicyPath $policy -MacroLevel L5 -WarningVariable warnings -WarningAction SilentlyContinue
        $results.ID | Should -Not -Contain 'LV-X'
        ($warnings -join ' ') | Should -Match 'LV-X'
    }

    It 'evaluates every rule without -MacroLevel' {
        @(Invoke-ThemisPolicy -PolicyPath $policy).Count | Should -Be 4
    }
}

Describe 'Backups during Enforce' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    BeforeEach {
        New-Item -Path 'TestRegistry:\ThemisJournal' -Force | Out-Null
        $backups = Join-Path $TestDrive ("journal_" + [guid]::NewGuid().ToString('N'))
        $policy = New-TestPolicy -Path (Join-Path $TestDrive 'journal.json') -Content @{
            Meta          = @{ Name = 'Journal'; Version = '1.0.0' }
            RegistryRules = @(
                @{ ID = 'J-1'; Name = 'First'; Path = 'TestRegistry:\ThemisJournal'; ValueName = 'A'; Value = 1; Type = 'DWord' }
                @{ ID = 'J-2'; Name = 'Second'; Path = 'TestRegistry:\ThemisJournal'; ValueName = 'B'; Value = 1; Type = 'DWord' }
            )
        }
    }

    It 'writes the backup after every changed rule, into the same file' {
        Mock -ModuleName ThemisRules Save-ThemisBackup { if ($File) { $File } else { Join-Path $Folder 'run.json' } }
        $results = Invoke-ThemisPolicy -PolicyPath $policy -Mode Enforce -BackupPath $backups
        Should -Invoke -ModuleName ThemisRules Save-ThemisBackup -Times 2 -Exactly
        Should -Invoke -ModuleName ThemisRules Save-ThemisBackup -Times 1 -Exactly -ParameterFilter { $File -like '*run.json' }
        $results.Backup | Select-Object -Unique | Should -BeLike '*run.json'
    }

    It 'never reuses the file of another run, even in the same second' {
        $a = (Invoke-ThemisPolicy -PolicyPath $policy -Mode Enforce -BackupPath $backups)[0].Backup
        Remove-Item 'TestRegistry:\ThemisJournal' -Recurse
        New-Item -Path 'TestRegistry:\ThemisJournal' -Force | Out-Null
        $b = (Invoke-ThemisPolicy -PolicyPath $policy -Mode Enforce -BackupPath $backups)[0].Backup
        $a | Should -Not -Be $b
        @(Get-ChildItem $backups -Filter '*.json').Count | Should -Be 2
        @(Get-ChildItem $backups -Filter '*.tmp').Count | Should -Be 0
    }
}

Describe 'Previous values are kept when a change fails halfway' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    It 'registry: a write that fails leaves nothing to undo' {
        New-Item -Path 'TestRegistry:\ThemisFail' -Force | Out-Null
        New-ItemProperty -Path 'TestRegistry:\ThemisFail' -Name 'V' -Value 3 -PropertyType DWord | Out-Null
        Mock -ModuleName ThemisRules New-ItemProperty { throw 'access denied' }
        $rule = [pscustomobject]@{ Path = 'TestRegistry:\ThemisFail'; ValueName = 'V'; Value = 1; Type = 'DWord' }
        $result = InModuleScope ThemisRules -Parameters @{ Rule = $rule } { param($Rule) Invoke-ThemisRegistryRule -Rule $Rule -Mode Enforce }
        $result.Status | Should -Be 'EnforceFailed'
        @($result.Previous).Count | Should -Be 0
    }

    It 'registry: keys changed before a failure are returned to undo, the failed one is not' {
        foreach ($k in 'A1', 'A2') {
            New-Item -Path "TestRegistry:\ThemisHalf\$k" -Force | Out-Null
            New-ItemProperty -Path "TestRegistry:\ThemisHalf\$k" -Name 'V' -Value 0 -PropertyType DWord | Out-Null
        }
        $script:writes = 0
        Mock -ModuleName ThemisRules New-ItemProperty {
            $script:writes++
            if ($script:writes -gt 1) { throw 'access denied' }
            Microsoft.PowerShell.Management\New-ItemProperty -LiteralPath $LiteralPath -Name $Name -Value $Value -PropertyType $PropertyType -Force | Out-Null
        }
        $rule = [pscustomobject]@{ Path = 'TestRegistry:\ThemisHalf\A*'; ValueName = 'V'; Value = 1; Type = 'DWord' }
        $result = InModuleScope ThemisRules -Parameters @{ Rule = $rule } { param($Rule) Invoke-ThemisRegistryRule -Rule $Rule -Mode Enforce }
        $result.Status | Should -Be 'EnforceFailed'
        @($result.Previous).Count | Should -Be 1
        @($result.Previous)[0].Value | Should -Be 0
    }

    It 'service: keeps the old startup type when the service then fails to start' {
        $script:svc = [pscustomobject]@{ Name = 'ThemisFake'; Status = 'Stopped'; StartType = 'Disabled' }
        $script:svc | Add-Member -MemberType ScriptMethod -Name Refresh -Value { }
        Mock -ModuleName ThemisRules Get-Service { $script:svc }
        Mock -ModuleName ThemisRules Set-Service { $script:svc.StartType = $StartupType }
        Mock -ModuleName ThemisRules Start-Service { throw 'the service did not start' }
        $rule = [pscustomobject]@{ Name = 'ThemisFake'; StartupType = 'Manual'; State = 'Running' }
        $result = InModuleScope ThemisRules -Parameters @{ Rule = $rule } { param($Rule) Invoke-ThemisServiceRule -Rule $Rule -Mode Enforce }
        $result.Status | Should -Be 'EnforceFailed'
        $result.Previous.StartupType | Should -Be 'Disabled'
        $result.Previous.State | Should -Be 'Stopped'
    }

    It 'service: reports EnforceFailed when the service is not as required after the change' {
        $script:svc = [pscustomobject]@{ Name = 'ThemisFake'; Status = 'Running'; StartType = 'Automatic' }
        $script:svc | Add-Member -MemberType ScriptMethod -Name Refresh -Value { }
        Mock -ModuleName ThemisRules Get-Service { $script:svc }
        Mock -ModuleName ThemisRules Set-Service { }   # accepted, but the service keeps its startup type
        $rule = [pscustomobject]@{ Name = 'ThemisFake'; StartupType = 'Disabled' }
        $result = InModuleScope ThemisRules -Parameters @{ Rule = $rule } { param($Rule) Invoke-ThemisServiceRule -Rule $Rule -Mode Enforce }
        $result.Status | Should -Be 'EnforceFailed'
        $result.IsCompliant | Should -BeFalse
        $result.Previous.StartupType | Should -Be 'Automatic'
    }
}

Describe 'Restoring as administrator' -Skip:(-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) {
    It 'treats a file the current user owns as untrusted' {
        $file = Join-Path $TestDrive 'mine.json'
        Set-Content -Path $file -Value '{}'
        InModuleScope ThemisRules -Parameters @{ File = $file } { param($File) Test-ThemisTrustedPath -Path $File } | Should -BeFalse
    }

    It 'trusts a system file that only administrators can change' {
        $file = Join-Path ([Environment]::GetFolderPath('System')) 'ntdll.dll'
        InModuleScope ThemisRules -Parameters @{ File = $file } { param($File) Test-ThemisTrustedPath -Path $File } | Should -BeTrue
    }

    It 'refuses to restore, elevated, a backup that users without elevation can edit' {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        Mock -ModuleName ThemisRules Invoke-ThemisPolicy { }
        $file = Join-Path $TestDrive 'tampered.json'
        '{ "Meta": { "Name": "Backup before enforcing X" } }' | Set-Content -Path $file
        Restore-ThemisBackup -Path $file -ErrorVariable failed -ErrorAction SilentlyContinue
        ($failed -join ' ') | Should -Match 'Not restored'
        Should -Invoke -ModuleName ThemisRules Invoke-ThemisPolicy -Times 0 -Exactly
    }

    It 'still previews such a backup with -WhatIf' {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        Mock -ModuleName ThemisRules Invoke-ThemisPolicy { }
        $file = Join-Path $TestDrive 'preview.json'
        '{ "Meta": { "Name": "Backup before enforcing X" } }' | Set-Content -Path $file
        Restore-ThemisBackup -Path $file -WhatIf
        Should -Invoke -ModuleName ThemisRules Invoke-ThemisPolicy -Times 1 -Exactly -ParameterFilter { $Mode -eq 'Audit' }
    }

    It 'does not change the permissions of a folder given with -BackupPath' {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        $folder = Join-Path $TestDrive 'custom-backups'
        InModuleScope ThemisRules -Parameters @{ Folder = $folder } { param($Folder) Initialize-ThemisBackupFolder -Folder $Folder -Confirm:$false }
        $reference = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'reference-folder') -Force
        $owner = { param($p) (Get-Acl -LiteralPath $p).GetOwner([System.Security.Principal.SecurityIdentifier]).Value }
        & $owner $folder | Should -Be (& $owner $reference.FullName)
    }
}

Describe 'Protected backup folder' -Skip:(-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop') -or -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Needs a real elevated session (the GitHub Actions runners are): the owner can only be set to
    # Administrators from an elevated token. ProgramData is redirected to the test drive.
    BeforeAll { $script:savedProgramData = $env:ProgramData }
    AfterAll { $env:ProgramData = $script:savedProgramData }

    It 'takes over a folder created beforehand and lets only SYSTEM and Administrators change it' {
        $env:ProgramData = Join-Path $TestDrive 'ProgramData'
        $folder = Join-Path (Join-Path $env:ProgramData 'ThemisRules') 'Backups'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        InModuleScope ThemisRules -Parameters @{ Folder = $folder } { param($Folder) Initialize-ThemisBackupFolder -Folder $Folder -Confirm:$false }
        foreach ($dir in $folder, (Split-Path $folder -Parent)) {
            InModuleScope ThemisRules -Parameters @{ Dir = $dir } { param($Dir) Test-ThemisTrustedPath -Path $Dir } | Should -BeTrue
        }
        $file = Join-Path $folder 'backup.json'
        Set-Content -Path $file -Value '{}'
        InModuleScope ThemisRules -Parameters @{ File = $file } { param($File) Test-ThemisTrustedPath -Path $File } | Should -BeTrue
    }
}
