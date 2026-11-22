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

    It 'registers the twelve providers' {
        (Get-ThemisProvider).Type | Should -Be @('AppLocker', 'AuditPolicy', 'Check', 'EventLog', 'Feature', 'FileSignature', 'FirewallProfile', 'FirewallRule', 'LocalGroupMember', 'Process', 'Registry', 'RootCertificate', 'ScheduledTask', 'SecureFolder', 'SecurityPolicy', 'Service', 'UserRights')
    }

    It 'keeps the old name Get-ThemisProviders as an alias' {
        (Get-Command Get-ThemisProviders).ResolvedCommandName | Should -Be 'Get-ThemisProvider'
    }
}
