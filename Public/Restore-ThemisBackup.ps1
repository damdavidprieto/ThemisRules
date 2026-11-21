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
        In an elevated session the backup file and its folder must be changeable only by SYSTEM,
        Administrators and TrustedInstaller, as the default elevated backup folder is (see
        Get-ThemisBackup). Otherwise any program running without elevation could edit the backup and
        choose what this elevated session writes, so the restore is refused. To restore such a file
        anyway, review it and copy it into that folder from an elevated session.

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
        if (-not $WhatIfPreference -and (Test-ThemisElevated)) {
            $full = (Resolve-Path -LiteralPath $Path).ProviderPath
            if (-not (Test-ThemisTrustedPath -Path $full) -or -not (Test-ThemisTrustedPath -Path (Split-Path -Path $full -Parent))) {
                Write-Error ("[Themis] Not restored: $full or its folder can be changed by users who are not administrators, " +
                    "so its content cannot be trusted in an elevated session. Review it and copy it to $(Get-ThemisBackupFolder) from an elevated session first.")
                return
            }
        }
        if ($PSCmdlet.ShouldProcess($Path, 'Restore the values saved in this backup')) {
            Invoke-ThemisPolicy -PolicyPath $Path -Mode Enforce -Confirm:$false
        }
        elseif ($WhatIfPreference) {
            Invoke-ThemisPolicy -PolicyPath $Path -Mode Audit -WhatIf:$false
        }
    }
}
