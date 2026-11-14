@{
    RootModule           = 'ThemisRules.psm1'
    ModuleVersion        = '1.3.0'
    GUID                 = 'ba3f140e-776e-4424-9491-9533f52e5052'
    Author               = 'David Prieto'
    CompanyName          = 'David Prieto'
    Copyright            = '(c) 2026 David Prieto. Licensed under the MIT License.'
    Description          = 'JSON policy engine for Windows compliance auditing and enforcement. Evaluates registry, service and process rules, filters them by hardening level (L1-L5) and exports JSON, CSV or HTML reports.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @('Invoke-ThemisPolicy', 'Export-ThemisReport', 'Get-ThemisProvider', 'New-ThemisPolicy')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    # Name from earlier versions, kept so existing scripts keep working.
    AliasesToExport      = @('Get-ThemisProviders')
    PrivateData          = @{
        PSData = @{
            Tags         = @('Compliance', 'Security', 'Hardening', 'Audit', 'Policy', 'Registry', 'Services', 'Windows', 'PSEdition_Desktop', 'PSEdition_Core')
            LicenseUri   = 'https://github.com/damdavidprieto/ThemisRules/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/damdavidprieto/ThemisRules'
            ReleaseNotes = 'See https://github.com/damdavidprieto/ThemisRules/blob/main/CHANGELOG.md'
        }
    }
}
