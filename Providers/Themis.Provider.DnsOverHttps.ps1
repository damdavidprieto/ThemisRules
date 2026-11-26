# ThemisRules DnsOverHttps provider: the DNS over HTTPS template of one DNS server (Windows 11 and later).
#
#   ServerAddress       The IP address of the DNS server, for example 9.9.9.9.
#   Template            Its DNS over HTTPS address, for example https://dns.quad9.net/dns-query.
#   AllowFallbackToUdp  Use plain DNS when HTTPS fails (default false: encryption or nothing).
#   AutoUpgrade         Use HTTPS automatically when this server is configured (default true).
#   Ensure              Present (default) or Absent.
#
# Windows encrypts queries to a server only when it knows its template. Windows knows some servers already; this
# provider adds or corrects the others. Whether every configured server has one is the DnsEncrypted fact (see
# Get-ThemisFact), for a Check rule. Changing templates needs an elevated session.

function Get-ThemisDohServer {
    <#
    .SYNOPSIS
        The DNS over HTTPS entry of a server ({ Template; AllowFallbackToUdp; AutoUpgrade }), or $null. Separate so the tests can mock it.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', '', Justification = 'Only called when the cmdlet exists (Windows 11).')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServerAddress)
    $entry = Get-DnsClientDohServerAddress -ServerAddress $ServerAddress -ErrorAction SilentlyContinue
    if (-not $entry) { return $null }
    return [pscustomobject]@{ Template = "$($entry.DohTemplate)"; AllowFallbackToUdp = [bool]$entry.AllowFallbackToUdp; AutoUpgrade = [bool]$entry.AutoUpgrade }
}

function Set-ThemisDohServer {
    <#
    .SYNOPSIS
        Adds, changes or (with -Remove) removes the DNS over HTTPS entry of a server.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', '', Justification = 'Only called when the cmdlets exist (Windows 11).')]
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$ServerAddress, [string]$Template, [bool]$AllowFallbackToUdp, [bool]$AutoUpgrade, [switch]$Remove)
    if (-not $PSCmdlet.ShouldProcess($ServerAddress, $(if ($Remove) { 'Remove DNS over HTTPS template' } else { "Set DNS over HTTPS template $Template" }))) { return }
    $exists = [bool](Get-DnsClientDohServerAddress -ServerAddress $ServerAddress -ErrorAction SilentlyContinue)
    if ($Remove) { if ($exists) { Remove-DnsClientDohServerAddress -ServerAddress $ServerAddress -ErrorAction Stop }; return }
    if ($exists) { $null = Set-DnsClientDohServerAddress -ServerAddress $ServerAddress -DohTemplate $Template -AllowFallbackToUdp $AllowFallbackToUdp -AutoUpgrade $AutoUpgrade -ErrorAction Stop }
    else { $null = Add-DnsClientDohServerAddress -ServerAddress $ServerAddress -DohTemplate $Template -AllowFallbackToUdp $AllowFallbackToUdp -AutoUpgrade $AutoUpgrade -ErrorAction Stop }
}

function Invoke-ThemisDnsOverHttpsRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null }
    $address = "$($Rule.ServerAddress)"
    $template = "$($Rule.Template)"
    $ensure = if ($Rule.Ensure) { "$($Rule.Ensure)" } else { 'Present' }
    $fallback = $false
    if ($null -ne $Rule.AllowFallbackToUdp) { $fallback = "$($Rule.AllowFallbackToUdp)" -in 'True', '1' }
    $upgrade = $true
    if ($null -ne $Rule.AutoUpgrade) { $upgrade = "$($Rule.AutoUpgrade)" -in 'True', '1' }
    $ip = $null
    $problem = $null
    if (-not [System.Net.IPAddress]::TryParse($address, [ref]$ip)) { $problem = "ServerAddress must be an IP address: '$address'." }
    elseif ($ensure -notin 'Present', 'Absent') { $problem = "Ensure must be Present or Absent: '$ensure'." }
    elseif ($ensure -eq 'Present' -and $template -notmatch '^https://[A-Za-z0-9.-]+(:\d+)?/[^\s"<>]*$') { $problem = "Template must be an https:// address: '$template'." }
    if ($problem) { $result.Status = 'Error'; $result.Reason = $problem; return $result }

    if (-not (Get-Command -Name 'Get-DnsClientDohServerAddress' -ErrorAction SilentlyContinue)) {
        $result.Status = 'NotApplicable'
        $result.IsCompliant = $true
        $result.Reason = 'This Windows has no DNS over HTTPS (Windows 11 and Windows Server 2022 or later).'
        return $result
    }
    try {
        $current = Get-ThemisDohServer -ServerAddress $address
        $result.Actual = if ($current) { $current.Template } else { 'None' }
        $result.Data = @{ ServerAddress = $address; Entry = $current }
        $compliant = if ($ensure -eq 'Absent') { -not $current }
        else { $current -and $current.Template -eq $template -and $current.AllowFallbackToUdp -eq $fallback -and $current.AutoUpgrade -eq $upgrade }
        if ($compliant) {
            $result.Status = 'Compliant'
            $result.IsCompliant = $true
            $result.Reason = if ($ensure -eq 'Present') { "$address uses DNS over HTTPS at $template." } else { "$address has no DNS over HTTPS template." }
            return $result
        }
        $result.Status = 'Non-Compliant'
        $result.Reason = if ($ensure -eq 'Absent') { "$address has the template $($current.Template); required: none." }
        elseif ($current) { "$address has the template $($current.Template) (fallback to plain DNS: $($current.AllowFallbackToUdp), automatic: $($current.AutoUpgrade)); required: $template, fallback $fallback, automatic $upgrade." }
        else { "$address has no DNS over HTTPS template; required: $template." }
        if ($Mode -ne 'Enforce') { return $result }
        if (-not (Test-ThemisElevated)) {
            $result.Status = 'NeedsElevation'
            $result.Reason = 'Changing DNS over HTTPS templates requires an elevated session (Run as administrator).'
            return $result
        }

        if ($ensure -eq 'Absent') { Set-ThemisDohServer -ServerAddress $address -Remove -Confirm:$false }
        else { Set-ThemisDohServer -ServerAddress $address -Template $template -AllowFallbackToUdp $fallback -AutoUpgrade $upgrade -Confirm:$false }
        $after = Get-ThemisDohServer -ServerAddress $address
        $ok = if ($ensure -eq 'Absent') { -not $after } else { $after -and $after.Template -eq $template -and $after.AllowFallbackToUdp -eq $fallback -and $after.AutoUpgrade -eq $upgrade }
        if (-not $ok) {
            $result.Status = 'EnforceFailed'
            $result.Reason = "The DNS over HTTPS template of $address did not change."
            return $result
        }
        $result.Previous = if ($current) { [ordered]@{ ServerAddress = $address; Template = $current.Template; AllowFallbackToUdp = $current.AllowFallbackToUdp; AutoUpgrade = $current.AutoUpgrade } }
        else { [ordered]@{ ServerAddress = $address; Ensure = 'Absent' } }
        $result.Actual = if ($after) { $after.Template } else { 'None' }
        $result.Status = 'Fixed'
        $result.IsCompliant = $true
        $result.Reason = if ($ensure -eq 'Present') { "$address now uses DNS over HTTPS at $template." } else { "The DNS over HTTPS template of $address was removed." }
    }
    catch {
        $result.Status = 'Error'
        $result.Reason = "Provider Error: $_"
    }
    return $result
}
