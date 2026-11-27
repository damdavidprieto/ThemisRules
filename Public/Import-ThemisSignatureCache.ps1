function Import-ThemisSignatureCache {
    <#
    .SYNOPSIS
        Reads signatures saved by Export-ThemisSignatureCache, so they are not checked again.

    .DESCRIPTION
        Adds the saved results to the ones of this session and returns how many were read. Each result is kept by
        path, size and modification time, so a program that changed since is checked again anyway.
        In an elevated session the file must be one that only SYSTEM, Administrators and TrustedInstaller can
        change: otherwise a program running without elevation could mark its own unsigned service as signed, and
        the elevated session would believe it. Such a file is refused with an error. A missing file reads nothing
        (the first run of a tool has none yet).

    .PARAMETER Path
        The file written by Export-ThemisSignatureCache.

    .EXAMPLE
        Import-ThemisSignatureCache -Path "$env:ProgramData\MyTool\signatures.json"
        Get-ThemisFact -Name SystemServicesSigned

        Reads the fact checking only the programs that changed since the file was saved.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = [System.IO.Path]::GetFullPath($PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path))
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { return 0 }
    if ((Test-ThemisElevated) -and -not (Test-ThemisTrustedPath -Path $full)) {
        throw "The signature cache $full can be changed by users without elevation; an elevated session does not trust it. Keep it in a folder only administrators can change."
    }
    $data = Get-Content -LiteralPath $full -Raw -Encoding UTF8 | ConvertFrom-Json
    if ("$($data.Format)" -ne 'ThemisRules signature cache v1') { throw "$full is not a signature cache written by Export-ThemisSignatureCache." }
    $count = 0
    foreach ($entry in @($data.Entries.PSObject.Properties)) {
        # path|size|ticks, as Themis writes it.
        if ($entry.Name -notmatch '^.+\|\d+\|\d+$' -or "$($entry.Value)" -notmatch '^[A-Za-z]+$') { continue }
        $script:ThemisSignatureCache[$entry.Name] = "$($entry.Value)"
        $count++
    }
    return $count
}
