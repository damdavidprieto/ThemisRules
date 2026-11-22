# ThemisRules SecureFolder provider: a folder that exists with exactly the given permissions.
#
#   Path     Absolute path of the folder.
#   Sddl     Its permissions (DACL) in SDDL, for example 'D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'. They
#            are compared in canonical form, so the order Windows stores the entries in does not matter.
#   Ensure   Absent (used by backups): the folder is given back the permissions of its parent and is
#            removed if it is empty. A folder with files is never removed.
# Only the permissions are written, not the owner, so it also works where taking ownership is not allowed.

function ConvertTo-ThemisCanonicalSddl {
    <#
    .SYNOPSIS
        The access part (D:...) of an SDDL string in the canonical form Windows uses.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Sddl)

    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetSecurityDescriptorSddlForm($Sddl, 'Access')
    return $security.GetSecurityDescriptorSddlForm('Access')
}

function Get-ThemisFolderSddl {
    <#
    .SYNOPSIS
        The access part of a folder's permissions, or $null when it does not exist.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $null }
    return (Get-Acl -LiteralPath $Path -ErrorAction Stop).GetSecurityDescriptorSddlForm('Access')
}

function Set-ThemisFolderDacl {
    <#
    .SYNOPSIS
        Writes only the permissions (DACL) of a folder. Set-Acl would also write the owner.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleTypes', '', Justification = 'FileSystemAclExtensions is only used on PowerShell 7, where DirectoryInfo has no SetAccessControl method.')]
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Sddl)

    if (-not $PSCmdlet.ShouldProcess($Path, "Set permissions to $Sddl")) { return }
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetSecurityDescriptorSddlForm($Sddl, 'Access')
    $directory = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($directory.PSObject.Methods['SetAccessControl']) { $directory.SetAccessControl($security) }               # Windows PowerShell 5.1
    else { [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.DirectoryInfo]$directory, $security) } # PowerShell 7
}

function Invoke-ThemisSecureFolderRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null }
    $path = "$($Rule.Path)"
    if (-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) {
        $result.Status = 'Error'
        $result.Reason = 'SecureFolder rules use Windows permissions (SDDL) and only run on Windows.'
        return $result
    }
    if (-not [System.IO.Path]::IsPathRooted($path) -or $path -notmatch '^[A-Za-z]:\\' -or $path -match '\.\.') {
        $result.Status = 'Error'
        $result.Reason = "Path must be an absolute folder path such as C:\ProgramData\MyApp: '$path'."
        return $result
    }
    $absent = $Rule.Ensure -eq 'Absent'
    $wanted = $null
    if (-not $absent) {
        try { $wanted = ConvertTo-ThemisCanonicalSddl -Sddl "$($Rule.Sddl)" }
        catch {
            $result.Status = 'Error'
            $result.Reason = "Sddl is not valid: $($_.Exception.Message)"
            return $result
        }
    }

    try {
        $current = Get-ThemisFolderSddl -Path $path
        $exists = $null -ne $current
        $result.Data = @{ Exists = $exists; Sddl = $current }
        $result.Actual = if ($exists) { $current } else { '(missing)' }
        $compliant = if ($absent) { -not $exists } else { $exists -and $current -eq $wanted }
        if ($compliant) {
            $result.Status = 'Compliant'
            $result.IsCompliant = $true
            $result.Reason = if ($absent) { "$path does not exist." } else { "$path has the required permissions." }
            return $result
        }

        $result.Status = 'Non-Compliant'
        $result.Reason = if ($absent) { "$path exists." } elseif ($exists) { "$path has other permissions: $current" } else { "$path does not exist." }
        if ($Mode -ne 'Enforce') { return $result }

        if ($absent) {
            # Inherit the parent's permissions again (with restricted ones it may not even be listable),
            # and remove the folder only if it is empty: data is never deleted.
            $result.Previous = [ordered]@{ Path = $path; Sddl = $current }
            Set-ThemisFolderDacl -Path $path -Sddl 'D:AI' -Confirm:$false
            if (@(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop).Count) {
                $result.Status = 'EnforceFailed'
                $result.Reason = "$path is not empty, so it was not removed; it has its parent's permissions again."
                return $result
            }
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            $result.Status = 'Fixed'; $result.IsCompliant = $true; $result.Reason = "$path removed."
            $result.Actual = '(missing)'; $result.Data = @{ Exists = $false; Sddl = $null }
            return $result
        }

        $result.Previous = if ($exists) { [ordered]@{ Path = $path; Sddl = $current } } else { [ordered]@{ Path = $path; Ensure = 'Absent' } }
        if (-not $exists) { New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop | Out-Null }
        Set-ThemisFolderDacl -Path $path -Sddl $wanted -Confirm:$false
        $after = Get-ThemisFolderSddl -Path $path
        $result.Data = @{ Exists = $true; Sddl = $after }
        $result.Actual = $after
        if ($after -eq $wanted) {
            $result.Status = 'Fixed'; $result.IsCompliant = $true; $result.Reason = "$path has the required permissions."
        }
        else {
            $result.Status = 'EnforceFailed'; $result.Reason = "$path still has other permissions: $after"
        }
    }
    catch {
        $result.Status = $(if ($result.Contains('Previous')) { 'EnforceFailed' } elseif ($_.Exception -is [System.UnauthorizedAccessException]) { 'NeedsElevation' } else { 'Error' })
        $result.Reason = "Provider Error: $_"
    }
    return $result
}
