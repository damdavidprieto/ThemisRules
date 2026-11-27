# ThemisRules RootCertificate provider: whether a certificate is in a trusted root store.
#
#   Thumbprint  SHA-1 thumbprint of the certificate (40 hexadecimal digits).
#   Store       LocalMachine (default) or CurrentUser.
#   Ensure      Absent (default) or Present.
# The root of an antivirus (Bitdefender, Kaspersky, ESET...) is never removed: Enforce leaves it and says so (Manual).
#   RawData     The certificate in Base64, for Present (restore rules carry it).
# A root certificate added by a program lets whoever holds its key impersonate any website or sign any program
# for this machine. Removing one records the certificate itself, so the restore rule puts it back exactly.
# LocalMachine needs an elevated session. Windows asks the user to confirm changes to the CurrentUser root store.

function Get-ThemisRootCertificate {
    <#
    .SYNOPSIS
        The certificate with that thumbprint in the root store, as Base64 ({ Subject; RawData }), or $null. Separate so the tests can mock it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Thumbprint, [Parameter(Mandatory = $true)][string]$Store)

    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', $Store)
    try {
        $s.Open('ReadOnly')
        $cert = @($s.Certificates | Where-Object { $_.Thumbprint -eq $Thumbprint }) | Select-Object -First 1
        if (-not $cert) { return $null }
        return [pscustomobject]@{ Subject = $cert.Subject; RawData = [Convert]::ToBase64String($cert.RawData) }
    }
    finally { $s.Close() }
}

function Set-ThemisRootCertificate {
    <#
    .SYNOPSIS
        Removes the certificate with that thumbprint from the root store, or adds the one given as Base64.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$Thumbprint,
        [Parameter(Mandatory = $true)][string]$Store,
        [Parameter(Mandatory = $true)][ValidateSet('Present', 'Absent')][string]$Ensure,
        [string]$RawData
    )

    if (-not $PSCmdlet.ShouldProcess("$Store\Root\$Thumbprint", "Make the root certificate $Ensure")) { return }
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', $Store)
    try {
        $s.Open('ReadWrite')
        if ($Ensure -eq 'Absent') {
            foreach ($cert in @($s.Certificates | Where-Object { $_.Thumbprint -eq $Thumbprint })) { $s.Remove($cert) }
        }
        else {
            $s.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [Convert]::FromBase64String($RawData))))
        }
    }
    finally { $s.Close() }
}

function Invoke-ThemisRootCertificateRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null }
    $thumb = "$($Rule.Thumbprint)".ToUpperInvariant() -replace '\s', ''
    $store = if ($Rule.Store) { "$($Rule.Store)" } else { 'LocalMachine' }
    $ensure = if ($Rule.Ensure) { "$($Rule.Ensure)" } else { 'Absent' }
    $problem = $null
    if ($thumb -notmatch '^[0-9A-F]{40}$') { $problem = "Thumbprint must be 40 hexadecimal digits: '$($Rule.Thumbprint)'." }
    elseif ($store -notin 'LocalMachine', 'CurrentUser') { $problem = "Store must be LocalMachine or CurrentUser: '$store'." }
    elseif ($ensure -notin 'Present', 'Absent') { $problem = "Ensure must be Present or Absent: '$ensure'." }
    elseif ($ensure -eq 'Present') {
        # The certificate to add must be the one the rule names: a restore rule cannot add another certificate.
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [Convert]::FromBase64String("$($Rule.RawData)"))
            if ($cert.Thumbprint -ne $thumb) { $problem = "RawData is a certificate with thumbprint $($cert.Thumbprint), not $thumb." }
        }
        catch { $problem = 'Ensure Present needs the certificate in Base64 in RawData.' }
    }
    if ($problem) { $result.Status = 'Error'; $result.Reason = $problem; return $result }

    try {
        $current = Get-ThemisRootCertificate -Thumbprint $thumb -Store $store
        $result.Actual = if ($current) { $current.Subject } else { 'Missing' }
        $result.Data = @{ Exists = [bool]$current; Subject = $(if ($current) { $current.Subject }) }
        $compliant = if ($ensure -eq 'Absent') { -not $current } else { [bool]$current }
        if ($compliant) {
            $result.Status = 'Compliant'
            $result.IsCompliant = $true
            $result.Reason = if ($current) { "$store root store trusts $($current.Subject)." } else { "$thumb is not in the $store root store." }
            return $result
        }
        $result.Status = 'Non-Compliant'
        $result.Reason = if ($current) { "$store root store trusts $($current.Subject) ($thumb); required: not trusted." } else { "$thumb is not in the $store root store; required: trusted." }
        if ($Mode -ne 'Enforce') { return $result }
        # An antivirus uses its root to inspect encrypted traffic: removing it here would break it without switching it off.
        if ($ensure -eq 'Absent' -and $current -and (Test-ThemisAntivirusRoot -Subject $current.Subject)) {
            $result.Status = 'Manual'
            $result.Reason = "$($current.Subject) belongs to an antivirus, so Themis does not remove it: turn off the scanning of encrypted connections in the antivirus, which removes it."
            return $result
        }
        if ($store -eq 'LocalMachine' -and -not (Test-ThemisElevated)) {
            $result.Status = 'NeedsElevation'
            $result.Reason = 'Changing the LocalMachine root store requires an elevated session (Run as administrator).'
            return $result
        }

        Set-ThemisRootCertificate -Thumbprint $thumb -Store $store -Ensure $ensure -RawData "$($Rule.RawData)" -Confirm:$false
        $after = Get-ThemisRootCertificate -Thumbprint $thumb -Store $store
        $ok = if ($ensure -eq 'Absent') { -not $after } else { [bool]$after }
        if (-not $ok) {
            $result.Status = 'EnforceFailed'
            $result.Reason = "The $store root store did not change (Windows may have restored it, or the change was declined)."
            return $result
        }
        $result.Previous = if ($current) { [ordered]@{ Thumbprint = $thumb; Store = $store; Ensure = 'Present'; RawData = $current.RawData } }
        else { [ordered]@{ Thumbprint = $thumb; Store = $store; Ensure = 'Absent' } }
        $result.Status = 'Fixed'
        $result.IsCompliant = $true
        $result.Reason = if ($ensure -eq 'Absent') { "Removed $($current.Subject) from the $store root store." } else { "Added $thumb to the $store root store." }
    }
    catch {
        $result.Status = 'Error'
        $result.Reason = "Provider Error: $_"
    }
    return $result
}
