function Get-ThemisFact {
    <#
    .SYNOPSIS
        Reads facts about this machine (Secure Boot, BitLocker, memory integrity, antivirus, updates...) for AppliesIf
        conditions and Check rules.

    .DESCRIPTION
        Returns one object with a property per fact. Invoke-ThemisPolicy and Invoke-ThemisRule read the facts their
        rules use on their own, so you only need this command to see the values, or to pass them to another tool.
        Only the sources of the facts you ask for are read, and nothing is changed. A fact that cannot be read (it
        needs elevation, or this Windows does not have it) is $null. Windows only; elsewhere every fact is $null.
        With -ListAvailable, returns the name, source and description of every built-in fact.

    .PARAMETER Name
        The facts to read. Defaults to all of them, which takes a few seconds (checking the signatures of the
        services is the slowest part).

    .PARAMETER ListAvailable
        List the built-in facts instead of reading them.

    .EXAMPLE
        Get-ThemisFact -Name SecureBootOn, BitLockerSystemDrive, HvciRunning

        Reads three facts.

    .EXAMPLE
        Get-ThemisFact -ListAvailable | Format-Table Name, Description

        Lists every built-in fact.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Read')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(ParameterSetName = 'Read', Position = 0)]
        [ArgumentCompleter({
                param($commandName, $parameterName, $wordToComplete)
                $null = $commandName, $parameterName
                & (Get-Module ThemisRules) { $script:ThemisFactCatalog.Keys } | Where-Object { $_ -like "$wordToComplete*" }
            })]
        [string[]]$Name,

        [Parameter(Mandatory = $true, ParameterSetName = 'List')]
        [switch]$ListAvailable
    )

    if ($ListAvailable) {
        foreach ($key in $script:ThemisFactCatalog.Keys) {
            [pscustomobject]@{ Name = $key; Source = $script:ThemisFactCatalog[$key].Source; Description = $script:ThemisFactCatalog[$key].Description }
        }
        return
    }
    $wanted = if ($Name) { $Name } else { @($script:ThemisFactCatalog.Keys) }
    foreach ($fact in $wanted) {
        if (-not $script:ThemisFactCatalog.Contains($fact)) { throw "Unknown fact '$fact'. Get-ThemisFact -ListAvailable lists them." }
    }
    # Each call reads the machine again.
    $script:ThemisRunCache = @{}
    $out = [ordered]@{}
    foreach ($fact in $wanted) { $out[$fact] = (Read-ThemisFactSource -Source $script:ThemisFactCatalog[$fact].Source)[$fact] }
    return [pscustomobject]$out
}
