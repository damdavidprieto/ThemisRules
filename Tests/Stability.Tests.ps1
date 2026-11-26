# Rule IDs and MacroLevel of the shipped baseline are a contract: other tools refer to rules by ID.
# Tests/Data/baseline-ids.json holds them. A test fails when an ID disappears or changes its MacroLevel, so the
# change is made on purpose: update the snapshot in the same commit and add a CHANGELOG line under Changed.
# New IDs are allowed without touching the snapshot.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../ThemisRules.psd1') -Force
    $path = (Get-ThemisBaseline -Name Windows-Workstation).Path
    $policy = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    $script:current = @{}
    $script:ruleCount = 0
    foreach ($section in $policy.PSObject.Properties) {
        if ($section.Name -eq 'Meta') { continue }
        foreach ($rule in @($section.Value)) {
            $script:ruleCount++
            $script:current["$($rule.ID)"] = "$($rule.MacroLevel)"
        }
    }
    $snapshot = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Data/baseline-ids.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $script:known = @{}
    foreach ($entry in $snapshot.Ids.PSObject.Properties) { $script:known[$entry.Name] = "$($entry.Value)" }
}

Describe 'Windows workstation baseline: stable rule IDs and levels' {
    It 'has no duplicate IDs' {
        $script:current.Count | Should -Be $script:ruleCount
    }

    It 'keeps every ID of the snapshot' {
        @($script:known.Keys | Where-Object { -not $script:current.ContainsKey($_) }) | Should -BeNullOrEmpty
    }

    It 'keeps the MacroLevel of every ID of the snapshot' {
        $changed = @($script:known.Keys | Where-Object { $script:current.ContainsKey($_) -and $script:current[$_] -ne $script:known[$_] } |
                ForEach-Object { "$_ $($script:known[$_]) -> $($script:current[$_])" })
        $changed | Should -BeNullOrEmpty
    }
}
