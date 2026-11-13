function Get-ThemisProviders {
    <#
    .SYNOPSIS
        Lists the rule providers ThemisRules can dispatch to.
    .DESCRIPTION
        Each provider handles one rule section of a policy: the "Registry" provider handles
        "RegistryRules", and so on.
    .EXAMPLE
        Get-ThemisProviders

        Type     Command                  PolicySection
        ----     -------                  -------------
        Process  Invoke-ThemisProcessRule ProcessRules
        Registry Invoke-ThemisRegistryRule RegistryRules
        Service  Invoke-ThemisServiceRule ServiceRules
    #>
    [CmdletBinding()]
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
