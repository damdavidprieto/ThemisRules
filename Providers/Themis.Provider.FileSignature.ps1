# ThemisRules FileSignature provider: a file must have a valid digital signature, optionally from one publisher.
#
#   Path          Path of the file; environment variables such as %ProgramFiles% are allowed.
#   Publisher     Optional: text that the signer must contain, such as 'O=Microsoft Corporation'.
#   AllowMissing  A missing file is NotApplicable instead of Non-Compliant (default $false).
# Enforce cannot sign a file: a file that does not comply is reported as Manual, with what to do. Use it to check
# that a program you rely on (an interpreter, an agent, a driver) is the one its publisher signed.

function Get-ThemisFileSignature {
    <#
    .SYNOPSIS
        Signature status and signer of a file ({ Status; Signer }), or $null when the file does not exist. Separate so the tests can mock it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    return [pscustomobject]@{ Status = "$($sig.Status)"; Signer = "$(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject })" }
}

function Invoke-ThemisFileSignatureRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $null = $Mode   # Nothing to apply: a signature cannot be fixed by enforcing.
    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null }
    if ([string]::IsNullOrWhiteSpace("$($Rule.Path)")) {
        $result.Status = 'Error'
        $result.Reason = 'FileSignature rule has no Path.'
        return $result
    }
    $path = [Environment]::ExpandEnvironmentVariables("$($Rule.Path)")
    try {
        $sig = Get-ThemisFileSignature -Path $path
        if (-not $sig) {
            if ($Rule.AllowMissing) {
                $result.Status = 'NotApplicable'
                $result.IsCompliant = $true
                $result.Reason = "$path does not exist."
            }
            else {
                $result.Status = 'Manual'
                $result.Reason = "$path does not exist."
            }
            $result.Data = @{ Missing = $true }
            return $result
        }
        $result.Actual = "$($sig.Status) $($sig.Signer)".Trim()
        $result.Data = @{ Missing = $false; Status = $sig.Status; Signer = $sig.Signer }
        $publisherOk = -not $Rule.Publisher -or $sig.Signer.IndexOf("$($Rule.Publisher)", [StringComparison]::OrdinalIgnoreCase) -ge 0
        if ($sig.Status -eq 'Valid' -and $publisherOk) {
            $result.Status = 'Compliant'
            $result.IsCompliant = $true
            $result.Reason = "$path is signed by $($sig.Signer)."
        }
        else {
            $result.Status = 'Manual'
            $result.Reason = if ($sig.Status -ne 'Valid') { "$path has no valid signature ($($sig.Status)): replace it with the publisher's original or remove it." }
            else { "$path is signed by $($sig.Signer), not by $($Rule.Publisher): replace it with the publisher's original or remove it." }
        }
    }
    catch {
        $result.Status = 'Error'
        $result.Reason = "Provider Error: $_"
    }
    return $result
}
