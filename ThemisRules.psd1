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
    FunctionsToExport    = @('Invoke-ThemisPolicy', 'Export-ThemisReport', 'Get-ThemisProviders', 'New-ThemisPolicy')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('Compliance', 'Security', 'Hardening', 'Audit', 'Policy', 'Registry', 'Windows', 'PSEdition_Desktop', 'PSEdition_Core')
            LicenseUri   = 'https://github.com/damdavidprieto/ThemisRules/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/damdavidprieto/ThemisRules'
            ReleaseNotes = @'
# 1.3.0

- Fixed: the module exported no functions (1.2.0 loaded its engine as a separate global
  module, so Invoke-ThemisPolicy was not part of ThemisRules). It now exports
  Invoke-ThemisPolicy, Export-ThemisReport, Get-ThemisProviders and New-ThemisPolicy.
- Added Export-ThemisReport (JSON, CSV, HTML), which the 1.2.0 manifest listed but did not include.
- Correct project and license metadata (MIT), Windows PowerShell 5.1 minimum.
- The package now contains only the module files.

Full changelog: https://github.com/damdavidprieto/ThemisRules/blob/main/CHANGELOG.md
'@
        }
    }
}
