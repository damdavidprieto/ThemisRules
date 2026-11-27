function Export-ThemisSignatureCache {
    <#
    .SYNOPSIS
        Saves the signatures Themis has checked in this session, so the next session does not check them again.

    .DESCRIPTION
        The UnsignedSystemServices and SystemServicesSigned facts check the Authenticode signature of the program of
        every service that runs as SYSTEM, which takes seconds. Themis remembers each result by path, size and
        modification time (a changed file is checked again). This command writes those results to a JSON file, and
        Import-ThemisSignatureCache reads them back. Returns the file.
        A session that runs as administrator trusts what the file says: keep it in a folder only administrators can
        change (Import-ThemisSignatureCache refuses any other file in an elevated session). Supports -WhatIf.

    .PARAMETER Path
        The file to write.

    .EXAMPLE
        $null = Get-ThemisFact -Name SystemServicesSigned
        Export-ThemisSignatureCache -Path "$env:ProgramData\MyTool\signatures.json"

        Saves the signatures checked to read the fact.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.IO.FileInfo])]
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = [System.IO.Path]::GetFullPath($PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path))
    if (-not $PSCmdlet.ShouldProcess($full, "Save $($script:ThemisSignatureCache.Count) checked signature(s)")) { return }
    $entries = [ordered]@{}
    foreach ($key in @($script:ThemisSignatureCache.Keys | Sort-Object)) { $entries[$key] = $script:ThemisSignatureCache[$key] }
    $null = [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($full))
    [ordered]@{ Format = 'ThemisRules signature cache v1'; Saved = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Entries = $entries } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $full -Encoding UTF8
    return Get-Item -LiteralPath $full
}
