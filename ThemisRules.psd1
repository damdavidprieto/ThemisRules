@{
    RootModule        = 'ThemisRules.psm1'
    ModuleVersion     = '1.2.0'
    GUID              = 'ba3f140e-776e-4424-9491-9533f52e5052'
    Author            = 'Cassiel Security Team'
    CompanyName       = 'Cassiel Security'
    Copyright         = '(c) 2026 Cassiel Security. All rights reserved.'
    Description       = 'Universal Policy Engine for Security Auditing and Enforcement. Supports MacroLevel filtering, Registry/Service/Feature rules, and comprehensive compliance reporting.'
    FunctionsToExport = @('Invoke-ThemisPolicy', 'Export-ThemisReport')
    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags = @('Compliance', 'Security', 'Hardening', 'Themis')
        }
    }
}
