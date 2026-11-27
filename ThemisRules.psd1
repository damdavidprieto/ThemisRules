@{
    RootModule           = 'ThemisRules.psm1'
    ModuleVersion        = '2.0.0'
    GUID                 = 'ba3f140e-776e-4424-9491-9533f52e5052'
    Author               = 'David Prieto'
    CompanyName          = 'David Prieto'
    Copyright            = '(c) 2026 David Prieto. Licensed under the MIT License.'
    Description          = 'Audit and harden Windows with JSON policies. Ships a Windows 10/11 workstation baseline (L1-L3: UAC, credentials, SMB, RDP, printing, Kerberos, Credential Guard, audit policy, password and lockout policy, user rights, Defender and attack surface reduction, firewall, services) and 19 rule types (registry, services, features, audit and security policy, user rights, firewall profiles and rules, Defender settings, DNS over HTTPS, AppLocker, scheduled tasks, root certificates, event logs, local groups, protected folders, file signatures, processes and checks). Reads facts about the machine itself (Secure Boot, BitLocker, memory integrity, antivirus, updates) for conditions and checks. Audit or Enforce (-WhatIf), single rules or batches for tools that keep their own history, backups to undo Enforce, exceptions, severities, and JSON, CSV or HTML reports with weighted scores.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @('Invoke-ThemisPolicy', 'Invoke-ThemisRule', 'Export-ThemisReport', 'Get-ThemisBackup', 'Get-ThemisBaseline', 'Get-ThemisFact', 'Get-ThemisProvider', 'New-ThemisPolicy', 'Restore-ThemisBackup', 'Test-ThemisPolicy', 'Compare-ThemisResult')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('Compliance', 'Security', 'Hardening', 'Baseline', 'CIS', 'Audit', 'AuditPolicy', 'Firewall', 'Policy', 'Registry', 'Windows', 'PSEdition_Desktop', 'PSEdition_Core')
            LicenseUri   = 'https://github.com/damdavidprieto/ThemisRules/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/damdavidprieto/ThemisRules'
            ReleaseNotes = 'See https://github.com/damdavidprieto/ThemisRules/blob/main/CHANGELOG.md'
        }
    }
}
