function Get-ThemisProvider {
    <#
    .SYNOPSIS
        Lists the rule providers ThemisRules can dispatch to.
    .DESCRIPTION
        Each provider handles one rule section of a policy: the "Registry" provider handles
        "RegistryRules", and so on. Sections without a provider are skipped by
        Invoke-ThemisPolicy. The old name Get-ThemisProviders still works as an alias.
    .EXAMPLE
        Get-ThemisProvider

        Type     Command                  PolicySection
        ----     -------                  -------------
        Process  Invoke-ThemisProcessRule ProcessRules
        Registry Invoke-ThemisRegistryRule RegistryRules
        Service  Invoke-ThemisServiceRule ServiceRules
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    if ($script:ProviderCache.Count -eq 0) { Initialize-ThemisProviders }

    foreach ($type in $script:ProviderCache.Keys | Sort-Object) {
        [PSCustomObject]@{
            Type          = $type
            Command       = $script:ProviderCache[$type]
            PolicySection = "${type}Rules"
        }
    }
}


# Name from earlier versions, kept so existing scripts keep working.
New-Alias -Name Get-ThemisProviders -Value Get-ThemisProvider
