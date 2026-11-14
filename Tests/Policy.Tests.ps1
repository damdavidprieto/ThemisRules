BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../ThemisRules.psd1') -Force

    # TestRegistry: is a temporary registry key that Pester creates and deletes per block.
    function New-TestPolicy {
        param([string]$Path, [hashtable]$Content)
        $Content | ConvertTo-Json -Depth 5 | Set-Content -Path $Path
        $Path
    }
}

Describe 'Invoke-ThemisPolicy' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    BeforeEach {
        New-Item -Path 'TestRegistry:\Themis' -Force | Out-Null
        New-ItemProperty -Path 'TestRegistry:\Themis' -Name 'Hardened' -Value 1 -PropertyType DWord | Out-Null
        New-ItemProperty -Path 'TestRegistry:\Themis' -Name 'Telemetry' -Value 3 -PropertyType DWord | Out-Null

        $policy = New-TestPolicy -Path (Join-Path $TestDrive 'policy.json') -Content @{
            Meta          = @{ Name = 'Test policy'; Version = '1.0.0' }
            RegistryRules = @(
                @{ ID = 'REG-1'; MacroLevel = 'L1'; Name = 'Hardened'; Path = 'TestRegistry:\Themis'; ValueName = 'Hardened'; Value = 1; Type = 'DWord' },
                @{ ID = 'REG-2'; MacroLevel = 'L1'; Name = 'Telemetry off'; Path = 'TestRegistry:\Themis'; ValueName = 'Telemetry'; Value = 0; Type = 'DWord' },
                @{ ID = 'REG-3'; MacroLevel = 'L3'; Name = 'Missing value'; Path = 'TestRegistry:\Themis'; ValueName = 'Absent'; Value = 'x'; Type = 'String' }
            )
            ServiceRules  = @(
                @{ ID = 'SVC-1'; MacroLevel = 'L2'; Name = "ThemisNoSuchService$(Get-Random)"; Action = 'Absent' }
            )
        }
    }

    It 'audits every rule and reports compliance per rule' {
        $results = Invoke-ThemisPolicy -PolicyPath $policy -Mode Audit

        $results.Count | Should -Be 4
        ($results | Where-Object ID -EQ 'REG-1').Status | Should -Be 'Compliant'
        ($results | Where-Object ID -EQ 'REG-2').Status | Should -Be 'Non-Compliant'
        ($results | Where-Object ID -EQ 'REG-2').Actual | Should -Be 3
        ($results | Where-Object ID -EQ 'REG-3').Status | Should -Be 'MissingValue'
        ($results | Where-Object ID -EQ 'SVC-1').IsCompliant | Should -BeTrue
    }

    It 'adds policy metadata to each result' {
        $result = Invoke-ThemisPolicy -PolicyPath $policy | Select-Object -First 1
        $result.Policy | Should -Be 'Test policy'
        $result.PolicyPath | Should -Be $policy
    }

    It 'evaluates only rules up to -MacroLevel' {
        $results = Invoke-ThemisPolicy -PolicyPath $policy -MacroLevel L1
        $results.ID | Should -Be @('REG-1', 'REG-2')
    }

    It 'does not change anything in Audit mode' {
        Invoke-ThemisPolicy -PolicyPath $policy -Mode Audit | Out-Null
        (Get-ItemProperty 'TestRegistry:\Themis').Telemetry | Should -Be 3
    }

    It 'fixes non-compliant registry values in Enforce mode' {
        $result = Invoke-ThemisPolicy -PolicyPath $policy -Mode Enforce -MacroLevel L1 | Where-Object ID -EQ 'REG-2'

        $result.Status | Should -Be 'Fixed'
        (Get-ItemProperty 'TestRegistry:\Themis').Telemetry | Should -Be 0
    }

    It 'reports a missing policy file as an error' {
        Invoke-ThemisPolicy -PolicyPath (Join-Path $TestDrive 'nope.json') -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
}

Describe 'Rule safety checks' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    It 'refuses a registry rule whose Path points at the file system, even in Enforce mode' {
        $target = Join-Path $TestDrive 'not-a-key'
        $policy = New-TestPolicy -Path (Join-Path $TestDrive 'fs.json') -Content @{
            RegistryRules = @(@{ ID = 'FS-1'; MacroLevel = 'L1'; Name = 'Escape'; Path = $target; ValueName = 'Attributes'; Value = 'Hidden'; Type = 'String' })
        }

        $result = Invoke-ThemisPolicy -PolicyPath $policy -Mode Enforce

        $result.Status | Should -Be 'Error'
        $result.Reason | Should -Match 'not a registry path'
        Test-Path $target | Should -BeFalse
    }

    It 'refuses process rules with wildcard names' {
        $policy = New-TestPolicy -Path (Join-Path $TestDrive 'proc.json') -Content @{
            ProcessRules = @(@{ ID = 'PROC-1'; MacroLevel = 'L1'; Name = '*'; State = 'Absent' })
        }
        $result = Invoke-ThemisPolicy -PolicyPath $policy -Mode Audit
        $result.Status | Should -Be 'Error'
        $result.Reason | Should -Match 'wildcard'
    }

    It 'refuses service rules with wildcard names' {
        $policy = New-TestPolicy -Path (Join-Path $TestDrive 'svc.json') -Content @{
            ServiceRules = @(@{ ID = 'SVC-W'; MacroLevel = 'L1'; Name = 'Win*'; Action = 'Absent' })
        }
        $result = Invoke-ThemisPolicy -PolicyPath $policy -Mode Audit
        $result.Status | Should -Be 'Error'
        $result.Reason | Should -Match 'wildcard'
    }
}

Describe 'Get-ThemisProvider' {
    It 'ignores matching functions defined outside the module' {
        function global:Invoke-ThemisSpoofRule { param($Rule, $Mode) @{ Status = 'Compliant'; IsCompliant = $true } }
        try {
            Import-Module (Join-Path $PSScriptRoot '../ThemisRules.psd1') -Force
            (Get-ThemisProvider).Type | Should -Be @('Process', 'Registry', 'Service')
        }
        finally {
            Remove-Item Function:\Invoke-ThemisSpoofRule -ErrorAction SilentlyContinue
        }
    }
}

Describe 'New-ThemisPolicy' {
    It 'creates a policy that Invoke-ThemisPolicy can read without warnings' {
        $path = Join-Path $TestDrive 'new.json'
        New-ThemisPolicy -Path $path -Name 'Empty' | Should -Not -BeNullOrEmpty
        (Get-Content $path -Raw | ConvertFrom-Json).Meta.Name | Should -Be 'Empty'
        Invoke-ThemisPolicy -PolicyPath $path -WarningVariable warnings | Should -BeNullOrEmpty
        $warnings | Should -BeNullOrEmpty
    }

    It 'does not replace an existing file without -Force' {
        $path = Join-Path $TestDrive 'existing.json'
        Set-Content -Path $path -Value 'keep me'
        { New-ThemisPolicy -Path $path } | Should -Throw
        Get-Content $path | Should -Be 'keep me'
        New-ThemisPolicy -Path $path -Force | Should -Not -BeNullOrEmpty
    }

    It 'supports -WhatIf' {
        $path = Join-Path $TestDrive 'whatif.json'
        New-ThemisPolicy -Path $path -WhatIf
        $path | Should -Not -Exist
    }
}

Describe 'Enforce with -WhatIf' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    BeforeEach {
        New-Item -Path 'TestRegistry:\ThemisWhatIf' -Force | Out-Null
        New-ItemProperty -Path 'TestRegistry:\ThemisWhatIf' -Name 'Setting' -Value 1 -PropertyType DWord | Out-Null
        $policy = New-TestPolicy -Path (Join-Path $TestDrive 'whatif-policy.json') -Content @{
            RegistryRules = @(@{ ID = 'W-1'; MacroLevel = 'L1'; Name = 'Setting'; Path = 'TestRegistry:\ThemisWhatIf'; ValueName = 'Setting'; Value = 0; Type = 'DWord' })
        }
    }

    It 'only audits, without changing the system' {
        $result = Invoke-ThemisPolicy -PolicyPath $policy -Mode Enforce -WhatIf
        $result.Status | Should -Be 'Non-Compliant'
        (Get-ItemProperty 'TestRegistry:\ThemisWhatIf').Setting | Should -Be 1
    }
}

Describe 'Example policies' {
    BeforeDiscovery {
        $script:examplePolicies = Get-ChildItem -Path (Join-Path $PSScriptRoot '../Examples') -Filter '*.json' |
            ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } }
    }

    It '<Name> uses only sections that have a provider' -ForEach $examplePolicies {
        $policy = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        $sections = $policy.PSObject.Properties.Name | Where-Object { $_ -ne 'Meta' }
        $supported = (Get-ThemisProvider).PolicySection
        $sections | Where-Object { $_ -notin $supported } | Should -BeNullOrEmpty
        $policy.Meta.Name | Should -Not -BeNullOrEmpty
    }

    It '<Name> runs in Audit mode' -ForEach $examplePolicies -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
        $results = @(Invoke-ThemisPolicy -PolicyPath $Path -Mode Audit -WarningVariable warnings)
        $results.Count | Should -BeGreaterThan 0
        $warnings | Should -BeNullOrEmpty
    }
}

Describe 'Export-ThemisReport' {
    BeforeAll {
        $results = @(
            [PSCustomObject]@{ Policy = 'P'; ID = 'A'; Type = 'Registry'; Name = 'Ok <rule>'; MacroLevel = 'L1'; Status = 'Compliant'; IsCompliant = $true; Reason = 'fine' },
            [PSCustomObject]@{ Policy = 'P'; ID = 'B'; Type = 'Service'; Name = 'Bad'; MacroLevel = 'L2'; Status = 'Non-Compliant'; IsCompliant = $false; Reason = 'off' }
        )
    }

    It 'writes JSON with a summary and the results' {
        $file = $results | Export-ThemisReport -Path (Join-Path $TestDrive 'r.json')
        $report = Get-Content $file.FullName -Raw | ConvertFrom-Json
        $report.Summary.Total | Should -Be 2
        $report.Summary.Score | Should -Be 50
        $report.Results.ID | Should -Be @('A', 'B')
    }

    It 'writes CSV with one row per result' {
        $file = Export-ThemisReport -InputObject $results -Path (Join-Path $TestDrive 'r.csv')
        @(Import-Csv $file.FullName).Count | Should -Be 2
    }

    It 'writes HTML with the score and encoded values' {
        $file = $results | Export-ThemisReport -Path (Join-Path $TestDrive 'r.html')
        $html = Get-Content $file.FullName -Raw
        $html | Should -Match '50%'
        $html | Should -Match 'Ok &lt;rule&gt;'
    }

    It 'rejects an unknown extension without -Format' {
        { $results | Export-ThemisReport -Path (Join-Path $TestDrive 'r.txt') } | Should -Throw
    }
}
