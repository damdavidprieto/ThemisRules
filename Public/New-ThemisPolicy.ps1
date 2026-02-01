function New-ThemisPolicy {
    <#
    .SYNOPSIS
        Creates a new empty ThemisRules policy file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [string]$Name = "New Policy"
    )

    $template = @{
        Meta          = @{
            Name    = $Name
            Version = "1.0"
            Author  = $env:USERNAME
            Created = (Get-Date).ToString("yyyy-MM-dd")
        }
        RegistryRules = @()
        ServiceRules  = @()
        ProcessRules  = @()
        WMIRules      = @()
    }

    $template | ConvertTo-Json -Depth 4 | Out-File -FilePath $Path -Encoding UTF8
    Write-Verbose "Created new policy at $Path"
    return (Get-Item $Path)
}
