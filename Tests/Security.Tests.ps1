BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../ThemisRules.psd1') -Force
}

Describe 'CSV report and formula injection' {
    It 'writes values that start with a formula character as text, not as formulas' {
        $results = @(
            [PSCustomObject]@{ ID = 'A'; Type = 'Registry'; Name = '=HYPERLINK("http://x","click")'; MacroLevel = 'L1'; Status = 'Non-Compliant'; IsCompliant = $false; Reason = '+1+1'; Actual = '-2' }
            [PSCustomObject]@{ ID = 'B'; Type = 'Service'; Name = '@SUM(A1)'; MacroLevel = 'L2'; Status = 'Compliant'; IsCompliant = $true; Reason = "`tTAB"; Actual = 'Running' }
        )
        $file = $results | Export-ThemisReport -Path (Join-Path $TestDrive 'injection.csv')
        $rows = @(Import-Csv -LiteralPath $file.FullName)
        $rows[0].Name | Should -BeExactly "'=HYPERLINK(`"http://x`",`"click`")"
        $rows[0].Reason | Should -BeExactly "'+1+1"
        $rows[0].Actual | Should -BeExactly "'-2"
        $rows[1].Name | Should -BeExactly "'@SUM(A1)"
        $rows[1].Reason | Should -Match "^'\t"
        $rows[1].Actual | Should -BeExactly 'Running'
    }

    It 'leaves ordinary values unchanged' {
        $results = @([PSCustomObject]@{ ID = 'C'; Type = 'Registry'; Name = 'Plain name'; MacroLevel = 'L1'; Status = 'Compliant'; IsCompliant = $true; Reason = 'ok'; Actual = '1' })
        $file = $results | Export-ThemisReport -Path (Join-Path $TestDrive 'plain.csv')
        (Import-Csv -LiteralPath $file.FullName).Name | Should -BeExactly 'Plain name'
    }
}

Describe 'Protected processes' {
    It 'refuses a process rule for <Name>' -TestCases @(
        @{ Name = 'lsass' }
        @{ Name = 'winlogon' }
        @{ Name = 'csrss' }
        @{ Name = 'services' }
    ) {
        $rule = [pscustomobject]@{ ID = 'P'; Name = $Name; State = 'Absent' }
        $result = InModuleScope ThemisRules -Parameters @{ Rule = $rule } { param($Rule) Invoke-ThemisProcessRule -Rule $Rule -Mode Enforce }
        $result.Status | Should -Be 'Error'
        $result.Reason | Should -Match 'core Windows process'
    }

    It 'does not refuse an ordinary application' {
        $rule = [pscustomobject]@{ ID = 'P'; Name = 'ThemisNoSuchApp'; State = 'Absent' }
        $result = InModuleScope ThemisRules -Parameters @{ Rule = $rule } { param($Rule) Invoke-ThemisProcessRule -Rule $Rule -Mode Audit }
        $result.Status | Should -Not -Be 'Error'
    }
}

Describe 'Invoke-ThemisPolicy surface' {
    It 'no longer accepts -Parallel' {
        (Get-Command Invoke-ThemisPolicy).Parameters.ContainsKey('Parallel') | Should -BeFalse
    }
}
