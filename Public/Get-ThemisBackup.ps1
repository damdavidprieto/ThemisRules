function Get-ThemisBackup {
    <#
    .SYNOPSIS
        Lists the backups that Invoke-ThemisPolicy -Mode Enforce saved before changing the system.

    .DESCRIPTION
        Each time Enforce changes at least one rule, it saves the previous values as a backup policy.
        This command lists those backups, newest first, with the time, the policy that was enforced,
        the number of values recorded and the path to pass to Restore-ThemisBackup.

    .PARAMETER Path
        Folder to look in. Defaults to the folder Invoke-ThemisPolicy uses.

    .EXAMPLE
        Get-ThemisBackup | Select-Object -First 5

        Shows the five most recent backups.

    .EXAMPLE
        Get-ThemisBackup | Select-Object -First 1 | Restore-ThemisBackup -WhatIf

        Shows what restoring the latest backup would change.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$Path = (Get-ThemisBackupFolder)
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }
    foreach ($file in Get-ChildItem -LiteralPath $Path -Filter '*.json' -File | Sort-Object Name -Descending) {
        try {
            $backup = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        }
        catch {
            Write-Warning "Skipping $($file.Name): not a valid backup ($($_.Exception.Message))."
            continue
        }
        $rules = @($backup.PSObject.Properties | Where-Object Name -Like '*Rules' | ForEach-Object { $_.Value })
        [PSCustomObject]@{
            Created      = $backup.Meta.Created
            Policy       = ($backup.Meta.Name -replace '^Backup before enforcing ', '')
            SourcePolicy = $backup.Meta.SourcePolicy
            Values       = $rules.Count
            Path         = $file.FullName
        }
    }
}
