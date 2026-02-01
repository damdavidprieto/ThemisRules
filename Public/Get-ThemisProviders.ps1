function Get-ThemisProviders {
    <#
    .SYNOPSIS
        Lists all loaded ThemisRules providers.
    .DESCRIPTION
        Reflects into the internal provider cache to show which modules (Registry, Service, etc.) are active.
    #>
    [CmdletBinding()]
    param()

    # Access internal scope variable if possible, or re-scan
    # Since scope is tricky across modules without 'InModuleScope', we verify by commands.
    
    $knownTypes = @("Registry", "Service", "File", "WMI", "Script", "Process")
    $providers = @()

    foreach ($type in $knownTypes) {
        $cmdlet = "Invoke-Themis${type}Rule"
        if (Get-Command $cmdlet -ErrorAction SilentlyContinue) {
            $providers += [PSCustomObject]@{
                Type    = $type
                Command = $cmdlet
                Status  = "Loaded"
            }
        }
    }

    return $providers
}
