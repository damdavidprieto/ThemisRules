function New-ThemisPolicy {
    <#
    .SYNOPSIS
        Creates an empty ThemisRules policy file to add rules to.

    .DESCRIPTION
        Writes a JSON policy with a Meta section (name, version, author, creation date) and
        empty RegistryRules, ServiceRules and ProcessRules sections, and returns the file.
        An existing file is only replaced with -Force. Supports -WhatIf and -Confirm.
        See the README or Schema/ThemisPolicy.schema.json for the rule format.

    .PARAMETER Path
        Path of the policy file to create.

    .PARAMETER Name
        Policy name stored in Meta.Name and shown in every result. Defaults to "New Policy".

    .PARAMETER Force
        Replace the file if it already exists.

    .EXAMPLE
        New-ThemisPolicy -Path .\baseline.json -Name 'Workstation baseline'

        Creates baseline.json, ready for rules.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$Name = 'New Policy',

        [switch]$Force
    )

    if ((Test-Path -LiteralPath $Path) -and -not $Force) {
        throw "Policy file '$Path' already exists. Use -Force to replace it."
    }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Create policy file')) { return }

    $template = [ordered]@{
        Meta          = [ordered]@{
            Name    = $Name
            Version = '1.0.0'
            Author  = [Environment]::UserName
            Created = (Get-Date).ToString('yyyy-MM-dd')
        }
        RegistryRules = @()
        ServiceRules  = @()
        ProcessRules  = @()
    }

    $template | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Path -Encoding UTF8
    Write-Verbose "Created new policy at $Path"
    return (Get-Item -LiteralPath $Path)
}
