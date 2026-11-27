BeforeAll {
    $manifestPath = Join-Path $PSScriptRoot '../ThemisRules.psd1'
    $manifest = Import-PowerShellDataFile -Path $manifestPath
    $module = Import-Module $manifestPath -Force -PassThru
}

Describe 'ThemisRules manifest' {
    It 'targets Windows PowerShell 5.1 or later' {
        [version]$manifest.PowerShellVersion | Should -BeGreaterOrEqual ([version]'5.1')
    }

    It 'exports every function listed in the manifest, and nothing else' {
        $exported = @($module.ExportedFunctions.Keys)
        $manifest.FunctionsToExport | Where-Object { $_ -notin $exported } | Should -BeNullOrEmpty
        $exported | Where-Object { $_ -notin $manifest.FunctionsToExport } | Should -BeNullOrEmpty
    }

    It 'keeps providers and engine internals private' {
        # Invoke-ThemisRule is public; the providers (Invoke-Themis<Type>Rule) are not.
        Get-Command -Module ThemisRules -Name 'Invoke-Themis*Rule', 'Initialize-ThemisProviders' -ErrorAction SilentlyContinue |
            Where-Object Name -NE 'Invoke-ThemisRule' | Should -BeNullOrEmpty
    }

    It 'does not load extra modules into the session' {
        Get-Module -Name 'Themis.*' | Should -BeNullOrEmpty
    }

    It 'has MIT license metadata pointing to this repository' {
        $manifest.Copyright | Should -Match 'MIT'
        $manifest.PrivateData.PSData.ProjectUri | Should -Be 'https://github.com/damdavidprieto/ThemisRules'
    }

    It 'registers every provider' {
        (Get-ThemisProvider).Type | Should -Be @('AppLocker', 'AuditPolicy', 'Check', 'DefenderPreference', 'DnsOverHttps', 'EventLog', 'Feature', 'FileSignature', 'FirewallProfile', 'FirewallRule', 'LocalGroupMember', 'Process', 'Registry', 'RootCertificate', 'ScheduledTask', 'SecureFolder', 'SecurityPolicy', 'Service', 'UserRights')
    }

    It 'no longer has the old name Get-ThemisProviders (removed in 2.0.0)' {
        # Only what this copy exports: Get-Command would load an older ThemisRules installed on the computer.
        $module.ExportedAliases.Count | Should -Be 0
        $module.ExportedCommands.Keys | Should -Not -Contain 'Get-ThemisProviders'
    }
}
