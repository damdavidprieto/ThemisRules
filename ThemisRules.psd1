@{
    RootModule           = 'ThemisRules.psm1'
    ModuleVersion        = '1.4.0'
    GUID                 = 'ba3f140e-776e-4424-9491-9533f52e5052'
    Author               = 'David Prieto'
    CompanyName          = 'David Prieto'
    Copyright            = '(c) 2026 David Prieto. Licensed under the MIT License.'
    Description          = 'Audit and harden Windows with JSON policies. Ships a Windows 10/11 workstation baseline (150 rules in levels L1-L3: UAC, credentials, SMB, RDP, audit policy, password and lockout policy, user rights, Defender and attack surface reduction, firewall, services) and supports ten rule types (registry, services, optional features, protected folders, audit policy, security policy, user rights, firewall, processes and manual checks), with AppliesIf and DependsOn conditions, single-rule evaluation for tools that keep their own history, with Audit/Enforce (-WhatIf), backups to undo Enforce, and JSON, CSV or HTML reports.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @('Invoke-ThemisPolicy', 'Invoke-ThemisRule', 'Export-ThemisReport', 'Get-ThemisBackup', 'Get-ThemisBaseline', 'Get-ThemisProvider', 'New-ThemisPolicy', 'Restore-ThemisBackup')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    # Name from earlier versions, kept so existing scripts keep working.
    AliasesToExport      = @('Get-ThemisProviders')
    PrivateData          = @{
        PSData = @{
            Tags         = @('Compliance', 'Security', 'Hardening', 'Baseline', 'CIS', 'Audit', 'AuditPolicy', 'Firewall', 'Policy', 'Registry', 'Windows', 'PSEdition_Desktop', 'PSEdition_Core')
            LicenseUri   = 'https://github.com/damdavidprieto/ThemisRules/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/damdavidprieto/ThemisRules'
            ReleaseNotes = 'See https://github.com/damdavidprieto/ThemisRules/blob/main/CHANGELOG.md'
        }
    }
}
