# ThemisRules 2.0: built-in facts, rule batches, exceptions, severities, and the DefenderPreference and
# DnsOverHttps providers.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../ThemisRules.psd1') -Force
    $script:onWindows = $IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop'
}

Describe 'Get-ThemisFact' {
    It 'lists every built-in fact with its source and description' {
        $list = @(Get-ThemisFact -ListAvailable)
        $list.Count | Should -BeGreaterThan 35
        $list.Name | Should -Contain 'SecureBootOn'
        @($list | Where-Object { -not $_.Description -or -not $_.Source }).Count | Should -Be 0
    }

    It 'reads only the facts asked for, and refuses an unknown one' {
        Mock -ModuleName ThemisRules Read-ThemisOSFact { @{ OSBuild = 26100; OSName = 'Windows 11 Pro' } }
        Mock -ModuleName ThemisRules Read-ThemisFirmwareFact { @{ SecureBootOn = $true } }
        $f = Get-ThemisFact -Name OSBuild, OSName
        $f.OSBuild | Should -Be 26100
        @($f.PSObject.Properties).Count | Should -Be 2
        if ($script:onWindows) { Should -Invoke -ModuleName ThemisRules Read-ThemisOSFact -Times 1 -Exactly }
        Should -Invoke -ModuleName ThemisRules Read-ThemisFirmwareFact -Times 0 -Exactly
        { Get-ThemisFact -Name NoSuchFact } | Should -Throw '*Unknown fact*'
    }

    It 'reads the real machine without failing (every fact is a value or $null)' -Skip:(-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) {
        $f = Get-ThemisFact -Name OSBuild, IsElevated, SecureBootOn, HvciRunning, DefenderMode, UpdatesRecent, HasPrinters
        $f.OSBuild | Should -BeGreaterThan 10000
        $f.IsElevated | Should -BeOfType [bool]
        foreach ($name in 'SecureBootOn', 'HvciRunning', 'UpdatesRecent', 'HasPrinters') {
            if ($null -ne $f.$name) { $f.$name | Should -BeOfType [bool] }
        }
    }
}

Describe 'Fact helpers' {
    It 'decodes the state of an antivirus' {
        InModuleScope ThemisRules {
            $on = ConvertFrom-ThemisAntivirusState -Name 'AV' -ProductState 0x61100
            $on.Enabled | Should -BeTrue
            $on.UpToDate | Should -BeTrue
            $old = ConvertFrom-ThemisAntivirusState -Name 'AV' -ProductState 0x61110
            $old.UpToDate | Should -BeFalse
            (ConvertFrom-ThemisAntivirusState -Name 'AV' -ProductState 0x60100).Enabled | Should -BeFalse
        }
    }

    It 'finds the newest security update, or the newest update when none is marked' {
        InModuleScope ThemisRules {
            $fixes = @(
                [pscustomobject]@{ Description = 'Security Update'; InstalledOn = [datetime]'2026-10-01' }
                [pscustomobject]@{ Description = 'Update'; InstalledOn = [datetime]'2026-11-01' }
                [pscustomobject]@{ Description = 'Security Update'; InstalledOn = [datetime]'2026-10-20' }
            )
            Get-ThemisLastSecurityUpdate -Fixes $fixes | Should -Be ([datetime]'2026-10-20')
            Get-ThemisLastSecurityUpdate -Fixes @($fixes[1]) | Should -Be ([datetime]'2026-11-01')
            Get-ThemisLastSecurityUpdate -Fixes @() | Should -BeNullOrEmpty
        }
    }

    It 'recognizes drivers that give direct access to hardware, and the program of a service' {
        InModuleScope ThemisRules {
            Test-ThemisHwAccessDriver '\??\C:\Windows\System32\drivers\RTCore64.sys' | Should -BeTrue
            Test-ThemisHwAccessDriver 'C:\Windows\System32\drivers\tcpip.sys' | Should -BeFalse
            Get-ThemisServiceProgram '"C:\Program Files\App\svc.exe" -run' | Should -Be 'C:\Program Files\App\svc.exe'
            Get-ThemisServiceProgram 'C:\App\svc.exe /k' | Should -Be 'C:\App\svc.exe'
        }
    }
}

Describe 'Facts read by the rules' {
    BeforeEach {
        Mock -ModuleName ThemisRules Read-ThemisFirmwareFact { @{ SecureBootOn = $true; UefiFirmware = $true } }
        Mock -ModuleName ThemisRules Read-ThemisOSFact { @{ OSBuild = 26100 } }
    }

    It 'reads a built-in fact a Check rule uses, unless the caller gives it or -NoFactCollection is set' -Skip:(-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) {
        $rule = @{ ID = 'CK'; Name = 'Secure Boot'; Fact = 'SecureBootOn'; Expected = $true }
        (Invoke-ThemisRule -Type Check -Rule $rule).Status | Should -Be 'Compliant'
        (Invoke-ThemisRule -Type Check -Rule $rule -Facts @{ SecureBootOn = $false }).Status | Should -Be 'Manual'
        (Invoke-ThemisRule -Type Check -Rule $rule -NoFactCollection).Status | Should -Be 'Unknown'
        Should -Invoke -ModuleName ThemisRules Read-ThemisOSFact -Times 0 -Exactly
    }

    It 'uses them in AppliesIf, and a policy reads each source once' -Skip:(-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) {
        $policy = Join-Path $TestDrive 'facts.json'
        @{
            Meta       = @{ Name = 'Facts'; Version = '1.0.0' }
            CheckRules = @(
                @{ ID = 'C1'; Name = 'Secure Boot'; Fact = 'SecureBootOn'; Expected = $true }
                @{ ID = 'C2'; Name = 'UEFI'; Fact = 'UefiFirmware'; Expected = $true; AppliesIf = @{ OSBuild = @{ ge = 22000 } } }
                @{ ID = 'C3'; Name = 'Old Windows only'; Fact = 'UefiFirmware'; Expected = $true; AppliesIf = @{ OSBuild = @{ lt = 22000 } } }
            )
        } | ConvertTo-Json -Depth 6 | Set-Content -Path $policy
        $r = Invoke-ThemisPolicy -PolicyPath $policy
        ($r | Where-Object ID -EQ 'C1').Status | Should -Be 'Compliant'
        ($r | Where-Object ID -EQ 'C2').Status | Should -Be 'Compliant'
        ($r | Where-Object ID -EQ 'C3').Status | Should -Be 'NotApplicable'
        Should -Invoke -ModuleName ThemisRules Read-ThemisFirmwareFact -Times 1 -Exactly
        Should -Invoke -ModuleName ThemisRules Read-ThemisOSFact -Times 1 -Exactly
    }
}

Describe 'Rule batches' -Skip:(-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) {
    BeforeEach {
        New-Item -Path 'TestRegistry:\Batch' -Force | Out-Null
        New-ItemProperty -Path 'TestRegistry:\Batch' -Name 'A' -Value 1 -PropertyType DWord | Out-Null
        Mock -ModuleName ThemisRules Read-ThemisOSFact { @{ OSBuild = 26100 } }
    }

    It 'evaluates the rules of the pipeline, in order, with DependsOn between them' {
        $items = @(
            @{ Type = 'Registry'; Rule = @{ ID = 'B1'; Name = 'A'; Path = 'TestRegistry:\Batch'; ValueName = 'A'; Value = 2; Type = 'DWord' } }
            [pscustomobject]@{ Type = 'Registry'; Rule = @{ ID = 'B2'; Name = 'B'; Path = 'TestRegistry:\Batch'; ValueName = 'B'; Value = 1; Type = 'DWord'; DependsOn = @('B1') } }
        )
        $audit = @($items | Invoke-ThemisRule)
        $audit.ID | Should -Be @('B1', 'B2')
        $audit[0].Status | Should -Be 'Non-Compliant'
        $audit[1].Status | Should -Not -Be 'Skipped'
        $enforce = @($items | Invoke-ThemisRule -Mode Enforce)
        $enforce[0].Status | Should -Be 'Fixed'
        $enforce[1].Status | Should -Be 'Fixed'
        (Get-ItemProperty 'TestRegistry:\Batch').B | Should -Be 1
    }

    It 'reads the facts once for the whole pipeline, and again on the next call' {
        $items = 1..3 | ForEach-Object { @{ Type = 'Check'; Rule = @{ ID = "C$_"; Name = 'Build'; Fact = 'OSBuild'; Expected = 26100 } } }
        @($items | Invoke-ThemisRule).Status | Should -Be @('Compliant', 'Compliant', 'Compliant')
        Should -Invoke -ModuleName ThemisRules Read-ThemisOSFact -Times 1 -Exactly
        $null = $items | Invoke-ThemisRule
        Should -Invoke -ModuleName ThemisRules Read-ThemisOSFact -Times 2 -Exactly
    }

    It 'refuses an item without Type and Rule' {
        { @{ Rule = @{ ID = 'X' } } | Invoke-ThemisRule } | Should -Throw '*Type and Rule*'
    }
}

Describe 'Exceptions' -Skip:(-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) {
    BeforeAll {
        $script:policy = Join-Path $TestDrive 'exceptions-policy.json'
        @{
            Meta          = @{ Name = 'Exceptions'; Version = '1.0.0' }
            RegistryRules = @(
                @{ ID = 'E1'; Name = 'A is 2'; Path = 'TestRegistry:\Exc'; ValueName = 'A'; Value = 2; Type = 'DWord' }
                @{ ID = 'E2'; Name = 'B is 2'; Path = 'TestRegistry:\Exc'; ValueName = 'B'; Value = 2; Type = 'DWord' }
            )
        } | ConvertTo-Json -Depth 6 | Set-Content -Path $script:policy
    }
    BeforeEach {
        New-Item -Path 'TestRegistry:\Exc' -Force | Out-Null
        New-ItemProperty -Path 'TestRegistry:\Exc' -Name 'A' -Value 1 -PropertyType DWord | Out-Null
        New-ItemProperty -Path 'TestRegistry:\Exc' -Name 'B' -Value 1 -PropertyType DWord | Out-Null
    }

    It 'marks an accepted deviation Excepted, and Enforce leaves it as it is' {
        $exceptions = @(@{ ID = 'E1'; Reason = 'Needed by the backup software'; Owner = 'IT'; Until = (Get-Date).AddDays(30).ToString('yyyy-MM-dd') })
        $r = Invoke-ThemisPolicy -PolicyPath $script:policy -Mode Enforce -Exceptions $exceptions -NoBackup
        $e1 = $r | Where-Object ID -EQ 'E1'
        $e1.Status | Should -Be 'Excepted'
        $e1.Reason | Should -Match 'by IT until .*Needed by the backup software'
        $e1.Exception.Owner | Should -Be 'IT'
        ($r | Where-Object ID -EQ 'E2').Status | Should -Be 'Fixed'
        (Get-ItemProperty 'TestRegistry:\Exc').A | Should -Be 1
    }

    It 'reads exceptions from a file, ignores expired ones with a warning, and warns about unknown IDs' {
        $file = Join-Path $TestDrive 'exceptions.json'
        @{ Exceptions = @(
                @{ ID = 'E1'; Reason = 'Old'; Until = '2020-01-01' }
                @{ ID = 'E9'; Reason = 'Not in the policy' }
            ) } | ConvertTo-Json -Depth 4 | Set-Content -Path $file
        $r = Invoke-ThemisPolicy -PolicyPath $script:policy -Exceptions $file -WarningVariable warned -WarningAction SilentlyContinue
        ($r | Where-Object ID -EQ 'E1').Status | Should -Be 'Non-Compliant'
        "$warned" | Should -Match 'E1 expired'
        "$warned" | Should -Match 'E9 names a rule the policy does not have'
    }

    It 'keeps a compliant rule Compliant, and refuses an exception without a reason' {
        Set-ItemProperty -Path 'TestRegistry:\Exc' -Name 'A' -Value 2
        (Invoke-ThemisPolicy -PolicyPath $script:policy -Exceptions @(@{ ID = 'E1'; Reason = 'x' }) | Where-Object ID -EQ 'E1').Status | Should -Be 'Compliant'
        { Invoke-ThemisPolicy -PolicyPath $script:policy -Exceptions @(@{ ID = 'E1' }) } | Should -Throw '*ID and a Reason*'
        { Invoke-ThemisPolicy -PolicyPath $script:policy -Exceptions @(@{ ID = 'E1'; Reason = 'x'; Until = 'tomorrow' }) } | Should -Throw '*not a date*'
    }
}

Describe 'Severity, references and scores' {
    It 'adds Severity (Medium when not given) and References to the results, and warns about an unknown severity' -Skip:(-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) {
        New-Item -Path 'TestRegistry:\Sev' -Force | Out-Null
        $r = Invoke-ThemisRule -Type Registry -Rule @{ ID = 'S1'; Name = 'x'; Path = 'TestRegistry:\Sev'; ValueName = 'X'; Value = 1; Type = 'DWord'; Severity = 'High'; References = @('CIS 1.1.1') }
        $r.Severity | Should -Be 'High'
        $r.References | Should -Be @('CIS 1.1.1')
        (Invoke-ThemisRule -Type Registry -Rule @{ ID = 'S2'; Name = 'x'; Path = 'TestRegistry:\Sev'; ValueName = 'X'; Value = 1; Type = 'DWord' }).Severity | Should -Be 'Medium'
        $odd = Invoke-ThemisRule -Type Registry -Rule @{ ID = 'S3'; Name = 'x'; Path = 'TestRegistry:\Sev'; ValueName = 'X'; Value = 1; Type = 'DWord'; Severity = 'Huge' } -WarningVariable warned -WarningAction SilentlyContinue
        $odd.Severity | Should -Be 'Medium'
        "$warned" | Should -Match 'unknown Severity'
    }

    It 'checks Severity in Test-ThemisPolicy and accepts References on any rule' {
        $policy = Join-Path $TestDrive 'severity.json'
        @{
            Meta         = @{ Name = 'Severity'; Version = '1.0.0' }
            ServiceRules = @(
                @{ ID = 'V1'; Name = 'RemoteRegistry'; StartupType = 'Disabled'; Severity = 'High'; References = @('CIS 5.1') }
                @{ ID = 'V2'; Name = 'Spooler'; StartupType = 'Disabled'; Severity = 'Urgent' }
            )
        } | ConvertTo-Json -Depth 6 | Set-Content -Path $policy
        $problems = @(Test-ThemisPolicy -Path $policy)
        $problems.Count | Should -Be 1
        $problems[0].ID | Should -Be 'V2'
        $problems[0].Problem | Should -Match 'Severity'
    }

    It 'weighs the score by severity and leaves exceptions out of it' {
        $results = @(
            [pscustomobject]@{ Policy = 'P'; ID = 'A'; Severity = 'Critical'; Status = 'Non-Compliant'; IsCompliant = $false }
            [pscustomobject]@{ Policy = 'P'; ID = 'B'; Severity = 'Low'; Status = 'Compliant'; IsCompliant = $true }
            [pscustomobject]@{ Policy = 'P'; ID = 'C'; Severity = 'Medium'; Status = 'Compliant'; IsCompliant = $true }
            [pscustomobject]@{ Policy = 'P'; ID = 'D'; Severity = 'High'; Status = 'Excepted'; IsCompliant = $false }
        )
        $file = $results | Export-ThemisReport -Path (Join-Path $TestDrive 'score.json')
        $summary = (Get-Content $file.FullName -Raw | ConvertFrom-Json).Summary
        $summary.Excepted | Should -Be 1
        $summary.Score | Should -Be 66.7
        # Compliant weight 1 + 2 out of 4 + 1 + 2.
        $summary.WeightedScore | Should -Be 42.9
        $summary.NonCompliantBySeverity.Critical | Should -Be 1
        $html = $results | Export-ThemisReport -Path (Join-Path $TestDrive 'score.html')
        Get-Content $html.FullName -Raw | Should -Match 'Weighted by severity: <strong>42.9%'
    }
}

Describe 'DefenderPreference provider' {
    BeforeEach {
        $script:pref = [pscustomobject]@{ PUAProtection = 0; DisableRealtimeMonitoring = $false; AttackSurfaceReductionRules_Ids = @(); AttackSurfaceReductionRules_Actions = @() }
        $script:tamper = $false
        Mock -ModuleName ThemisRules Read-ThemisAntivirusFact { @{ DefenderActive = $true } }
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        Mock -ModuleName ThemisRules Get-ThemisMpPreference { $script:pref }
        Mock -ModuleName ThemisRules Set-ThemisMpPreference {
            if ($script:tamper) { return }
            if ($AsrRule) {
                $ids = @($script:pref.AttackSurfaceReductionRules_Ids); $actions = @($script:pref.AttackSurfaceReductionRules_Actions)
                $keep = @(for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i] -ne $AsrRule) { , @($ids[$i], $actions[$i]) } })
                if ($null -ne $AsrAction) { $keep += , @($AsrRule, $AsrAction) }
                $script:pref.AttackSurfaceReductionRules_Ids = @($keep | ForEach-Object { $_[0] })
                $script:pref.AttackSurfaceReductionRules_Actions = @($keep | ForEach-Object { $_[1] })
            }
            else { $script:pref.$Setting = $Value }
        }
    }

    It 'changes a setting, reads it back and restores the old value' {
        $rule = @{ ID = 'D1'; Name = 'PUA'; Setting = 'PUAProtection'; Value = 1 }
        (Invoke-ThemisRule -Type DefenderPreference -Rule $rule).Status | Should -Be 'Non-Compliant'
        $r = Invoke-ThemisRule -Type DefenderPreference -Rule $rule -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        $r.Verified | Should -BeTrue
        $script:pref.PUAProtection | Should -Be 1
        $null = Invoke-ThemisRule -Type DefenderPreference -Rule $r.Previous[0] -Mode Enforce
        $script:pref.PUAProtection | Should -Be 0
    }

    It 'adds an attack surface reduction rule and restores it as not configured' {
        $rule = @{ ID = 'D2'; Name = 'Block LSASS theft'; AsrRule = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; AsrAction = 'Block' }
        $r = Invoke-ThemisRule -Type DefenderPreference -Rule $rule -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        $r.Previous[0].AsrAction | Should -Be 'Absent'
        (Invoke-ThemisRule -Type DefenderPreference -Rule $rule).Status | Should -Be 'Compliant'
        $null = Invoke-ThemisRule -Type DefenderPreference -Rule $r.Previous[0] -Mode Enforce
        @($script:pref.AttackSurfaceReductionRules_Ids).Count | Should -Be 0
    }

    It 'says when Tamper Protection or a policy keeps the value' {
        $script:tamper = $true
        (Invoke-ThemisRule -Type DefenderPreference -Rule @{ ID = 'D3'; Name = 'Real-time'; Setting = 'DisableRealtimeMonitoring'; Value = $true } -Mode Enforce).Status | Should -Be 'EnforceFailed'
    }

    It 'does not apply when another antivirus is the active one, and refuses unknown settings' {
        Mock -ModuleName ThemisRules Read-ThemisAntivirusFact { @{ DefenderActive = $false } }
        (Invoke-ThemisRule -Type DefenderPreference -Rule @{ ID = 'D4'; Name = 'PUA'; Setting = 'PUAProtection'; Value = 1 }).Status | Should -Be 'NotApplicable'
        (Invoke-ThemisRule -Type DefenderPreference -Rule @{ ID = 'D5'; Name = 'x'; Setting = 'ExclusionPath'; Value = 'C:\' }).Status | Should -Be 'Error'
        (Invoke-ThemisRule -Type DefenderPreference -Rule @{ ID = 'D6'; Name = 'x'; Setting = 'PUAProtection'; Value = 7 }).Status | Should -Be 'Error'
    }
}

Describe 'DnsOverHttps provider' {
    BeforeEach {
        $script:doh = @{}
        Mock -ModuleName ThemisRules Get-Command { [pscustomobject]@{ Name = 'Get-DnsClientDohServerAddress' } } -ParameterFilter { $Name -eq 'Get-DnsClientDohServerAddress' }
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        Mock -ModuleName ThemisRules Get-ThemisDohServer { $script:doh[$ServerAddress] }
        Mock -ModuleName ThemisRules Set-ThemisDohServer {
            if ($Remove) { $script:doh.Remove($ServerAddress) }
            else { $script:doh[$ServerAddress] = [pscustomobject]@{ Template = $Template; AllowFallbackToUdp = $AllowFallbackToUdp; AutoUpgrade = $AutoUpgrade } }
        }
    }

    It 'adds the template of a server and restores by removing it' {
        $rule = @{ ID = 'N1'; Name = 'Quad9'; ServerAddress = '9.9.9.9'; Template = 'https://dns.quad9.net/dns-query' }
        (Invoke-ThemisRule -Type DnsOverHttps -Rule $rule).Status | Should -Be 'Non-Compliant'
        $r = Invoke-ThemisRule -Type DnsOverHttps -Rule $rule -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        $script:doh['9.9.9.9'].AllowFallbackToUdp | Should -BeFalse
        $script:doh['9.9.9.9'].AutoUpgrade | Should -BeTrue
        $null = Invoke-ThemisRule -Type DnsOverHttps -Rule $r.Previous[0] -Mode Enforce
        $script:doh.ContainsKey('9.9.9.9') | Should -BeFalse
    }

    It 'corrects a template that falls back to plain DNS, and restores the old settings' {
        $script:doh['1.1.1.1'] = [pscustomobject]@{ Template = 'https://cloudflare-dns.com/dns-query'; AllowFallbackToUdp = $true; AutoUpgrade = $false }
        $r = Invoke-ThemisRule -Type DnsOverHttps -Rule @{ ID = 'N2'; Name = 'Cloudflare'; ServerAddress = '1.1.1.1'; Template = 'https://cloudflare-dns.com/dns-query' } -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        $null = Invoke-ThemisRule -Type DnsOverHttps -Rule $r.Previous[0] -Mode Enforce
        $script:doh['1.1.1.1'].AllowFallbackToUdp | Should -BeTrue
    }

    It 'refuses addresses and templates that are not valid' {
        (Invoke-ThemisRule -Type DnsOverHttps -Rule @{ ID = 'N3'; Name = 'x'; ServerAddress = 'dns.example'; Template = 'https://x/dns-query' }).Status | Should -Be 'Error'
        (Invoke-ThemisRule -Type DnsOverHttps -Rule @{ ID = 'N4'; Name = 'x'; ServerAddress = '9.9.9.9'; Template = 'http://dns.quad9.net/dns-query' }).Status | Should -Be 'Error'
    }
}

Describe 'Workstation baseline 2.0' {
    It 'passes Test-ThemisPolicy, and its new rules have a description' {
        $path = (Get-ThemisBaseline -Name Windows-Workstation).Path
        @(Test-ThemisPolicy -Path $path).Count | Should -Be 0
        $policy = Get-Content $path -Raw | ConvertFrom-Json
        $all = @($policy.RegistryRules) + @($policy.CheckRules)
        foreach ($id in 'WIN-PRT-001', 'WIN-KRB-001', 'WIN-CRED-010', 'WIN-CRED-012', 'WIN-SYS-003', 'WIN-DEF-010') {
            ($all | Where-Object ID -EQ $id).Description | Should -Not -BeNullOrEmpty -Because $id
        }
        @($policy.RegistryRules | Where-Object Severity -EQ 'Critical').Count | Should -BeGreaterThan 0
    }
}
