BeforeDiscovery {
    $script:baselineFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot '../Baselines') -Filter '*.json' |
        ForEach-Object { @{ Name = $_.BaseName; Path = $_.FullName } }
    $script:isWindowsHost = $IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop'
}

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../ThemisRules.psd1') -Force
    $schemaPath = Join-Path $PSScriptRoot '../Schema/ThemisPolicy.schema.json'
    $elevated = InModuleScope ThemisRules { Test-ThemisElevated }
}

Describe 'Baseline <Name>' -ForEach $baselineFiles {
    BeforeAll {
        $text = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
        $policy = $text | ConvertFrom-Json
        $rules = @($policy.PSObject.Properties | Where-Object Name -Like '*Rules' | ForEach-Object { $_.Value })
    }

    It 'is listed by Get-ThemisBaseline' {
        (Get-ThemisBaseline -Name $Name).Path | Should -Be (Get-Item $Path).FullName
    }

    It 'has metadata, unique IDs and a level on every rule' {
        $policy.Meta.Name | Should -Not -BeNullOrEmpty
        $policy.Meta.Version | Should -Not -BeNullOrEmpty
        $policy.Meta.AppliesTo | Should -Not -BeNullOrEmpty
        ($rules.ID | Group-Object | Where-Object Count -GT 1).Name | Should -BeNullOrEmpty
        $rules | Where-Object { $_.MacroLevel -notmatch '^L[1-5]$' } | Should -BeNullOrEmpty
    }

    It 'only uses sections that have a provider' {
        $supported = (Get-ThemisProvider).PolicySection
        $policy.PSObject.Properties.Name | Where-Object { $_ -ne 'Meta' -and $_ -notin $supported } | Should -BeNullOrEmpty
    }

    It 'validates against Schema/ThemisPolicy.schema.json' -Skip:(-not (Get-Command Test-Json -ErrorAction SilentlyContinue)) {
        Test-Json -Json $text -SchemaFile $schemaPath | Should -BeTrue
    }

    It 'points every registry rule at the registry' {
        $bad = $policy.RegistryRules | Where-Object { -not (InModuleScope ThemisRules -Parameters @{ P = $_.Path } { param($P) Test-ThemisRegistryPath -Path $P }) }
        $bad.ID | Should -BeNullOrEmpty
    }

    It 'uses audit subcategories that exist on this system' -Skip:(-not $isWindowsHost) {
        $known = (& auditpol.exe /list /subcategory:* /v) -match '\{[0-9A-F-]{36}\}' | ForEach-Object { ([regex]::Match($_, '\{[0-9A-F-]{36}\}')).Value }
        $policy.AuditPolicyRules | Where-Object { $_.Subcategory -notin $known } | ForEach-Object ID | Should -BeNullOrEmpty
    }

    It 'audits this machine; rules fail only for lack of elevation' -Skip:(-not $isWindowsHost) {
        $results = @(Invoke-ThemisPolicy -Baseline $Name -WarningVariable warnings)
        $warnings | Should -BeNullOrEmpty
        $results.Count | Should -Be $rules.Count
        $errors = $results | Where-Object Status -EQ 'Error'
        if ($elevated) {
            $errors | ForEach-Object { "$($_.ID): $($_.Reason)" } | Should -BeNullOrEmpty
        }
        else {
            $errors | Where-Object Reason -NotMatch 'elevated' | ForEach-Object { "$($_.ID): $($_.Reason)" } | Should -BeNullOrEmpty
        }
    }

    It 'filters by level' -Skip:(-not $isWindowsHost) {
        $l1 = @($rules | Where-Object MacroLevel -EQ 'L1').Count
        @(Invoke-ThemisPolicy -Baseline $Name -MacroLevel L1).Count | Should -Be $l1
    }
}

Describe 'Invoke-ThemisPolicy -Baseline' {
    It 'reports an unknown baseline and lists the available ones' {
        Invoke-ThemisPolicy -Baseline 'NoSuchBaseline' -ErrorVariable err -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        "$err" | Should -Match 'Windows-Workstation'
    }

    It 'refuses names that are paths' {
        { Invoke-ThemisPolicy -Baseline '..\..\secrets' } | Should -Throw
    }
}
