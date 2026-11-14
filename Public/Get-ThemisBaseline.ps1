function Get-ThemisBaseline {
    <#
    .SYNOPSIS
        Lists the baselines shipped with ThemisRules.

    .DESCRIPTION
        Returns one object per baseline in the module's Baselines folder, with its Name (to use
        with Invoke-ThemisPolicy -Baseline), Title, Version, Description, AppliesTo, Path and the
        number of rules per hardening level. A baseline is a normal policy file: copy it and
        edit the copy to adapt it.

    .PARAMETER Name
        Return only the baseline with this name. Wildcards are allowed.

    .EXAMPLE
        Get-ThemisBaseline | Format-Table Name, Version, Rules, L1, L2, L3

        Lists the baselines and how many rules each level has.

    .EXAMPLE
        Copy-Item (Get-ThemisBaseline -Name Windows-Workstation).Path .\my-baseline.json

        Copies a baseline to adapt it.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [SupportsWildcards()]
        [string]$Name = '*'
    )

    $folder = Join-Path (Split-Path $PSScriptRoot -Parent) 'Baselines'
    foreach ($file in Get-ChildItem -Path $folder -Filter '*.json' -File | Where-Object BaseName -Like $Name | Sort-Object BaseName) {
        $policy = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        $rules = @($policy.PSObject.Properties | Where-Object Name -Like '*Rules' | ForEach-Object { $_.Value })
        $levels = @{}
        foreach ($level in 'L1', 'L2', 'L3', 'L4', 'L5') { $levels[$level] = @($rules | Where-Object MacroLevel -EQ $level).Count }

        [PSCustomObject]@{
            Name        = $file.BaseName
            Title       = $policy.Meta.Name
            Version     = $policy.Meta.Version
            Description = $policy.Meta.Description
            AppliesTo   = $policy.Meta.AppliesTo
            Rules       = $rules.Count
            L1          = $levels.L1
            L2          = $levels.L2
            L3          = $levels.L3
            Path        = $file.FullName
        }
    }
}
