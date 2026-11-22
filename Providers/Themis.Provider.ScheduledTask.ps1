# ThemisRules ScheduledTask provider: whether a scheduled task exists and is enabled.
#
#   TaskPath   Folder of the task, starting and ending with "\" (default "\").
#   TaskName   Name of the task.
#   Ensure     Disabled (default), Enabled, Absent or Present.
#   Xml        Task definition, for Present (restore rules carry it).
# Disabled is met by a task that does not exist. Removing a task records its definition, so the restore rule
# registers it again exactly as it was. A scheduled task is how malware runs again after a restart; this lets a
# caller disable or remove one and still undo it.

function Get-ThemisScheduledTaskState {
    <#
    .SYNOPSIS
        Whether a task exists, its state and its XML definition, or $null when it does not exist. Separate so the tests can mock it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$TaskPath, [Parameter(Mandatory = $true)][string]$TaskName)

    $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) { return $null }
    $xml = Export-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    return [pscustomobject]@{ State = "$($task.State)"; Xml = "$xml" }
}

function Set-ThemisScheduledTaskState {
    <#
    .SYNOPSIS
        Disables, enables, removes or registers (from XML) a task.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$TaskPath,
        [Parameter(Mandatory = $true)][string]$TaskName,
        [Parameter(Mandatory = $true)][ValidateSet('Disabled', 'Enabled', 'Absent', 'Present')][string]$Ensure,
        [string]$Xml
    )

    if (-not $PSCmdlet.ShouldProcess("$TaskPath$TaskName", "Make the task $Ensure")) { return }
    switch ($Ensure) {
        'Disabled' { $null = Disable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop }
        'Enabled' { $null = Enable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop }
        'Absent' { Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Confirm:$false -ErrorAction Stop }
        'Present' { $null = Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Xml $Xml -Force -ErrorAction Stop }
    }
}

function Invoke-ThemisScheduledTaskRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null }
    $path = if ($Rule.TaskPath) { "$($Rule.TaskPath)" } else { '\' }
    $name = "$($Rule.TaskName)"
    $ensure = if ($Rule.Ensure) { "$($Rule.Ensure)" } else { 'Disabled' }
    if ($path -notmatch '^\\([^\\/:*?"<>|]+\\)*$' -or $name -notmatch '^[^\\/:*?"<>|]+$') {
        $result.Status = 'Error'
        $result.Reason = "TaskPath must start and end with '\' and TaskName must be a plain name: '$path' '$name'."
        return $result
    }
    if ($ensure -notin 'Disabled', 'Enabled', 'Absent', 'Present') {
        $result.Status = 'Error'
        $result.Reason = "Ensure must be Disabled, Enabled, Absent or Present: '$ensure'."
        return $result
    }
    if ($ensure -eq 'Present' -and -not $Rule.Xml) {
        $result.Status = 'Error'
        $result.Reason = 'Ensure Present needs the task definition in Xml.'
        return $result
    }
    $full = "$path$name"

    try {
        $task = Get-ThemisScheduledTaskState -TaskPath $path -TaskName $name
        $state = if ($task) { $task.State } else { 'Missing' }
        $result.Actual = $state
        $result.Data = @{ State = $state }
        $compliant = switch ($ensure) {
            'Disabled' { -not $task -or $state -eq 'Disabled' }
            'Enabled' { $task -and $state -ne 'Disabled' }
            'Absent' { -not $task }
            'Present' { [bool]$task }
        }
        if ($compliant) {
            $result.Status = 'Compliant'
            $result.IsCompliant = $true
            $result.Reason = if ($task) { "$full is $state." } else { "$full does not exist." }
            return $result
        }
        $result.Status = 'Non-Compliant'
        $result.Reason = if ($task) { "$full is $state; required: $ensure." } else { "$full does not exist; required: $ensure." }
        if ($Mode -ne 'Enforce') { return $result }
        if (-not $task -and $ensure -eq 'Enabled') {
            $result.Status = 'EnforceFailed'
            $result.Reason = "$full does not exist, so it cannot be enabled."
            return $result
        }

        try { Set-ThemisScheduledTaskState -TaskPath $path -TaskName $name -Ensure $ensure -Xml "$($Rule.Xml)" -Confirm:$false }
        catch [System.UnauthorizedAccessException] {
            $result.Status = 'NeedsElevation'
            $result.Reason = "Changing $full requires an elevated session (Run as administrator)."
            return $result
        }
        catch {
            if ("$($_.Exception.Message)" -match 'Access is denied|Acceso denegado|0x80070005') {
                $result.Status = 'NeedsElevation'
                $result.Reason = "Changing $full requires an elevated session (Run as administrator)."
                return $result
            }
            throw
        }

        $after = Get-ThemisScheduledTaskState -TaskPath $path -TaskName $name
        $afterState = if ($after) { $after.State } else { 'Missing' }
        $result.Actual = $afterState
        $result.Data = @{ State = $afterState }
        $ok = switch ($ensure) {
            'Disabled' { -not $after -or $afterState -eq 'Disabled' }
            'Enabled' { $after -and $afterState -ne 'Disabled' }
            'Absent' { -not $after }
            'Present' { [bool]$after }
        }
        if (-not $ok) {
            $result.Status = 'EnforceFailed'
            $result.Reason = "$full is still $afterState."
            return $result
        }
        # How to put it back: the old state, or the whole definition when the task was removed.
        $result.Previous = if (-not $task) { [ordered]@{ TaskPath = $path; TaskName = $name; Ensure = 'Absent' } }
        elseif ($ensure -eq 'Absent') { [ordered]@{ TaskPath = $path; TaskName = $name; Ensure = 'Present'; Xml = $task.Xml } }
        elseif ($state -eq 'Disabled') { [ordered]@{ TaskPath = $path; TaskName = $name; Ensure = 'Disabled' } }
        else { [ordered]@{ TaskPath = $path; TaskName = $name; Ensure = 'Enabled' } }
        $result.Status = 'Fixed'
        $result.IsCompliant = $true
        $result.Reason = "$full is now $(if ($after) { $afterState } else { 'removed' })."
    }
    catch {
        $result.Status = 'Error'
        $result.Reason = "Provider Error: $_"
    }
    return $result
}
