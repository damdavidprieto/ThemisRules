<#
    Quality checks shared by HermesConsoleUI, ArgosCCF and ThemisRules, modeled on the QA tests
    of the Sampler module template: every exported command is documented, the code passes
    PSScriptAnalyzer with the repository settings, the changelog follows Keep a Changelog and
    the manifest has the metadata the PowerShell Gallery shows.
#>

BeforeDiscovery {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $script:manifestFile = Get-ChildItem -Path $repoRoot -Filter '*.psd1' | Where-Object { $_.Name -ne 'PSScriptAnalyzerSettings.psd1' } | Select-Object -First 1
    $script:moduleName = $manifestFile.BaseName

    Get-Module $moduleName | Remove-Module -Force
    $module = Import-Module $manifestFile.FullName -Force -PassThru -WarningAction SilentlyContinue
    $script:commands = @($module.ExportedFunctions.Values | ForEach-Object { @{ Name = $_.Name } })
    Remove-Module $module -Force

    # Runtime source files: what build.ps1 packages, minus data files.
    $script:sourceFiles = @(Get-ChildItem -Path $repoRoot -Recurse -Include '*.ps1', '*.psm1', '*.psd1' |
            Where-Object { $_.FullName -notmatch '[\\/](\.git|\.github|output|tests?|Tests|examples|Examples|docs|Docs)[\\/]' } |
            Where-Object { $_.Name -notin 'build.ps1', 'PSScriptAnalyzerSettings.psd1' } |
            ForEach-Object { @{ Name = $_.FullName.Substring($repoRoot.Length + 1); Path = $_.FullName } })
}

BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $manifestFile = Get-ChildItem -Path $repoRoot -Filter '*.psd1' | Where-Object { $_.Name -ne 'PSScriptAnalyzerSettings.psd1' } | Select-Object -First 1
    $moduleName = $manifestFile.BaseName
    $manifest = Import-PowerShellDataFile -Path $manifestFile.FullName
    $settings = Join-Path $repoRoot 'PSScriptAnalyzerSettings.psd1'

    Get-Module $moduleName | Remove-Module -Force
    Import-Module $manifestFile.FullName -Force -WarningAction SilentlyContinue
}

AfterAll {
    Get-Module $moduleName | Remove-Module -Force
}

Describe 'Comment-based help for <Name>' -ForEach $commands {
    BeforeAll {
        $help = Get-Help -Name $Name -Full -ErrorAction Stop
        $command = Get-Command -Name $Name
        $commonParameters = [System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
        $parameters = @($command.Parameters.Keys | Where-Object { $_ -notin $commonParameters })
    }

    It 'has a synopsis' {
        $help.Synopsis | Should -Not -BeNullOrEmpty
        $help.Synopsis | Should -Not -Match "^\s*$([regex]::Escape($Name))\s"
    }

    It 'has a description of more than 40 characters' {
        ($help.Description.Text -join ' ').Trim().Length | Should -BeGreaterThan 40
    }

    It 'has at least one example' {
        @($help.Examples.Example).Count | Should -BeGreaterThan 0
        ($help.Examples.Example | Select-Object -First 1).Code | Should -Not -BeNullOrEmpty
    }

    It 'describes every parameter' {
        $undocumented = foreach ($parameter in $parameters) {
            $entry = $help.Parameters.Parameter | Where-Object Name -EQ $parameter
            if (-not ($entry.Description.Text -join '').Trim()) { $parameter }
        }
        $undocumented | Should -BeNullOrEmpty
    }

    It 'is an advanced function' {
        $command.CmdletBinding | Should -BeTrue
    }
}

Describe 'PSScriptAnalyzer: <Name>' -ForEach $sourceFiles {
    It 'has no findings with the repository settings' {
        # PSScriptAnalyzer can throw a NullReferenceException the first time it runs in a new
        # process; the same call succeeds when repeated, so retry once.
        $findings = try { Invoke-ScriptAnalyzer -Path $Path -Settings $settings -ErrorAction Stop }
        catch { if ($_.Exception.Message -match 'Object reference') { Invoke-ScriptAnalyzer -Path $Path -Settings $settings } else { throw } }
        $findings | ForEach-Object { "$($_.RuleName) line $($_.Line): $($_.Message)" } | Should -BeNullOrEmpty
    }
}

Describe 'Changelog' {
    BeforeAll {
        $changelogPath = Join-Path $repoRoot 'CHANGELOG.md'
    }

    It 'exists at the repository root' {
        $changelogPath | Should -Exist
    }

    It 'follows Keep a Changelog' {
        $text = Get-Content -LiteralPath $changelogPath -Raw -Encoding UTF8
        $text | Should -Match 'keepachangelog\.com'
        $text | Should -Match '(?m)^## \[Unreleased\]'
    }

    It 'has an entry for the manifest version' {
        $text = Get-Content -LiteralPath $changelogPath -Raw -Encoding UTF8
        $text | Should -Match "(?m)^## \[$([regex]::Escape($manifest.ModuleVersion))\]"
    }
}

Describe 'Manifest' {
    It 'has the metadata the PowerShell Gallery shows' {
        $manifest.Author | Should -Not -BeNullOrEmpty
        $manifest.Description.Length | Should -BeGreaterThan 40
        $manifest.PrivateData.PSData.LicenseUri | Should -Match '^https://'
        $manifest.PrivateData.PSData.ProjectUri | Should -Match '^https://'
        $manifest.PrivateData.PSData.Tags | Should -Not -BeNullOrEmpty
    }

    It 'supports Windows PowerShell 5.1 and PowerShell 7' {
        [version]$manifest.PowerShellVersion | Should -Be ([version]'5.1')
        $manifest.CompatiblePSEditions | Should -Contain 'Desktop'
        $manifest.CompatiblePSEditions | Should -Contain 'Core'
    }

    It 'lists exports explicitly, without wildcards' {
        foreach ($key in 'FunctionsToExport', 'CmdletsToExport', 'VariablesToExport', 'AliasesToExport') {
            $manifest.Keys | Should -Contain $key
            @($manifest[$key]) -join ',' | Should -Not -Match '\*'
        }
    }

    It 'exports exactly the functions and aliases it lists' {
        $module = Get-Module $moduleName
        (@($module.ExportedFunctions.Keys | Sort-Object) -join ',') | Should -BeExactly (@($manifest.FunctionsToExport | Sort-Object) -join ',')
        (@($module.ExportedAliases.Keys | Sort-Object) -join ',') | Should -BeExactly (@($manifest.AliasesToExport | Sort-Object) -join ',')
    }
}
