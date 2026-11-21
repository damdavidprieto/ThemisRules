# Themis Service Provider
# Handles 'Service' type rules.
# Actions supported: State (Running/Stopped), StartupType (Automatic/Manual/Disabled), Action = Absent.

function Invoke-ThemisServiceRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $result = [ordered]@{
        Status      = "Unknown"
        IsCompliant = $false
        Reason      = ""
        Actual      = $null
    }

    # Get-Service treats the name as a wildcard pattern: a rule named "*" would match every
    # service and, with Action = Absent in Enforce mode, delete them. Only exact names are allowed.
    if ([string]::IsNullOrWhiteSpace($Rule.Name) -or [System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($Rule.Name)) {
        $result.Status = "Error"
        $result.Reason = "Service rule needs an exact service name without wildcards: '$($Rule.Name)'."
        return $result
    }

    try {
        $svc = Get-Service -Name $Rule.Name -ErrorAction SilentlyContinue | Select-Object -First 1

        if ($null -eq $svc) {
            # Service Missing
            # A service that is not installed cannot run: rules that only want it absent,
            # stopped or disabled are met.
            $wantsRunning = $Rule.State -eq 'Running' -or ($Rule.StartupType -and $Rule.StartupType -ne 'Disabled')
            if ($Rule.Action -eq "Absent" -or -not $wantsRunning) {
                $result.Status = "Compliant"
                $result.IsCompliant = $true
                $result.Reason = "Service is not installed."
                $result.Actual = "Missing"
                return $result
            }
            else {
                $result.Status = "MissingService"
                $result.Reason = "Required service '$($Rule.Name)' not installed."
                $result.Actual = "Missing"
                # Cannot enforce "Install" easily, so we return failed.
                return $result
            }
        }

        $result.Actual = "$($svc.Status) ($($svc.StartType))"
        $reasons = @()

        # What to restore. Only states and startup types a rule can express are recorded; a deleted
        # service cannot be brought back, so Action = Absent leaves nothing to restore.
        $previous = [ordered]@{ Name = $svc.Name }
        if ("$($svc.Status)" -in 'Running', 'Stopped') { $previous.State = "$($svc.Status)" }
        if ("$($svc.StartType)" -in 'Automatic', 'Manual', 'Disabled') { $previous.StartupType = "$($svc.StartType)" }

        # Check Startup Type
        $changed = $false
        try {
            if ($Rule.StartupType) {
                if ($svc.StartType -ne $Rule.StartupType) {
                    $reasons += "Startup mismatch (Expected: $($Rule.StartupType), Actual: $($svc.StartType))."

                    if ($Mode -eq "Enforce") {
                        $changed = $true
                        Set-Service -Name $svc.Name -StartupType $Rule.StartupType -ErrorAction Stop
                        $reasons += "[Fixed] Startup type set to $($Rule.StartupType)."
                    }
                }
            }

            # Check State
            if ($Rule.State) {
                if ($svc.Status -ne $Rule.State) {
                    $reasons += "State mismatch (Expected: $($Rule.State), Actual: $($svc.Status))."

                    if ($Mode -eq "Enforce") {
                        if ($Rule.State -notin 'Running', 'Stopped') { throw "Unsupported service State '$($Rule.State)'. Use Running or Stopped." }
                        $changed = $true
                        if ($Rule.State -eq "Running") { Start-Service -Name $svc.Name -ErrorAction Stop }
                        else { Stop-Service -Name $svc.Name -Force -ErrorAction Stop }
                        $reasons += "[Fixed] Service state changed to $($Rule.State)."
                    }
                }
            }
        }
        catch {
            # Part of the rule may already be applied (for example the startup type changed but the
            # service did not start): keep what to restore, so the backup can undo that part.
            if ($changed -and $previous.Count -gt 1) { $result.Previous = $previous }
            $result.Status = if ($changed) { 'EnforceFailed' } else { 'Error' }
            $result.Reason = (@($reasons) + "Failed: $($_.Exception.Message)") -join ' '
            $svc.Refresh()
            $result.Actual = "$($svc.Status) ($($svc.StartType))"
            return $result
        }

        # Check Action: Absent (Removal)
        if ($Rule.Action -eq "Absent") {
            $reasons += "Service exists but should be absent."
            if ($Mode -eq "Enforce") {
                Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                $null = & (Get-ThemisSystemTool 'sc.exe') delete $svc.Name
                if ($LASTEXITCODE -ne 0) { throw "sc.exe delete '$($svc.Name)' failed with exit code $LASTEXITCODE." }
                $reasons += "[Fixed] Service deleted via SC."
            }
        }

        # Finalize
        if ($reasons.Count -gt 0) {
            if ($Mode -eq "Enforce") {
                if ($Rule.Action -eq 'Absent') {
                    $result.IsCompliant = $true
                    $result.Status = "Fixed"
                    $reasons += 'A deleted service cannot be restored from a backup.'
                }
                else {
                    if ($changed -and $previous.Count -gt 1) { $result.Previous = $previous }
                    # Read the service again instead of assuming the change worked.
                    $svc.Refresh()
                    $startupOk = -not $Rule.StartupType -or $svc.StartType -eq $Rule.StartupType
                    $stateOk = -not $Rule.State -or $svc.Status -eq $Rule.State
                    if ($startupOk -and $stateOk) {
                        $result.IsCompliant = $true
                        $result.Status = "Fixed"
                    }
                    else {
                        $result.IsCompliant = $false
                        $result.Status = "EnforceFailed"
                        $reasons += "After the change the service is $($svc.Status) ($($svc.StartType))."
                    }
                }
            }
            else {
                $result.IsCompliant = $false
                $result.Status = "Non-Compliant"
            }
            $result.Reason = $reasons -join " "
        }
        else {
            $result.IsCompliant = $true
            $result.Status = "Compliant"
            $result.Reason = "Service matches configuration."
        }

        # Refresh Actual if changed
        if ($Rule.Action -ne 'Absent' -or $Mode -ne 'Enforce') {
            $svc.Refresh()
            $result.Actual = "$($svc.Status) ($($svc.StartType))"
        }
        else { $result.Actual = 'Deleted' }

    }
    catch {
        $result.Status = "Error"
        $result.Reason = "Provider Error: $_"
    }

    return $result
}
