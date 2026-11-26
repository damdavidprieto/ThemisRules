function Get-ThemisServiceProgram {
    <#
    .SYNOPSIS
        Returns the program a service command line runs.

    .DESCRIPTION
        Takes the command line of a service (the PathName of Win32_Service, or ImagePath in the registry) and
        returns the program: the quoted part when it starts with a quote, otherwise everything up to the first
        ".exe", otherwise the first word. Unquoted paths with spaces are why this is needed: in
        C:\Program Files\App\svc.exe -run, splitting at the first space would give C:\Program. Returns $null for an
        empty line. The \??\ prefix of driver paths is not removed.

    .PARAMETER PathName
        The command line of the service. Accepts pipeline input, also by the property name PathName.

    .EXAMPLE
        Get-ThemisServiceProgram 'C:\Program Files\App\svc.exe -run'

        Returns C:\Program Files\App\svc.exe.

    .EXAMPLE
        Get-CimInstance Win32_Service | Get-ThemisServiceProgram

        Lists the program of every service.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [AllowNull()][AllowEmptyString()]
        [string]$PathName
    )

    process {
        if (-not $PathName) { return $null }
        $p = $PathName.Trim()
        if ($p.StartsWith('"')) {
            $end = $p.IndexOf('"', 1)
            if ($end -gt 1) { return $p.Substring(1, $end - 1) }
            return $null
        }
        if ($p -match '^(.+?\.exe)\b') { return $Matches[1] }
        return ($p -split '\s+')[0]
    }
}
