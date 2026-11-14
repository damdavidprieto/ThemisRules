function Restore-ThemisBackup {
    <#
    .SYNOPSIS
        Puts back the values that an Enforce run changed, from one of its backups.

    .DESCRIPTION
        A backup is a policy that holds the previous value of every rule Enforce changed: registry
        values (including removing values that did not exist), service state and startup type,
        audit policy, security policy, user rights and firewall settings. Restoring applies it
        with Invoke-ThemisPolicy -Mode Enforce and returns the results. Stopped processes and
        deleted services cannot be restored. Restoring also saves a backup, so it can be undone too.
        With -WhatIf nothing changes: it audits the backup instead, so the Non-Compliant results
        are the values that restoring would change. Run it elevated, like the Enforce run it undoes.

    .PARAMETER Path
        Backup file, as listed by Get-ThemisBackup. Accepts pipeline input from Get-ThemisBackup.

    .EXAMPLE
        Get-ThemisBackup | Select-Object -First 1 | Restore-ThemisBackup

        Restores the values changed by the most recent Enforce run.

    .EXAMPLE
        Restore-ThemisBackup -Path $results[0].Backup -WhatIf

        Shows what restoring the backup of a given run would change.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject[]], [object[]])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Path
    )

    process {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            Write-Error "[Themis] Backup not found: $Path"
            return
        }
        if ($PSCmdlet.ShouldProcess($Path, 'Restore the values saved in this backup')) {
            Invoke-ThemisPolicy -PolicyPath $Path -Mode Enforce -Confirm:$false
        }
        elseif ($WhatIfPreference) {
            Invoke-ThemisPolicy -PolicyPath $Path -Mode Audit -WhatIf:$false
        }
    }
}
