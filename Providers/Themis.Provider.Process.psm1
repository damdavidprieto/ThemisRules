<#
.SYNOPSIS
    Themis Process Provider
.DESCRIPTION
    Handles 'Process' type rules.
    Audits if a process is running. Enforce = Stop-Process.
#>

function Invoke-ThemisProcessRule {
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

    try {
        $procs = Get-Process -Name $Rule.Name -ErrorAction SilentlyContinue
        
        $isRunning = ($null -ne $procs)
        $result.Actual = if ($isRunning) { "Running ($($procs.Count))" } else { "Not Running" }

        if ($Rule.State -eq "Absent") {
            if ($isRunning) {
                $result.Status = "Non-Compliant"
                $result.Reason = "Process '$($Rule.Name)' is running (Blacklisted)."
                
                if ($Mode -eq "Enforce") {
                    Stop-Process -Name $Rule.Name -Force -ErrorAction SilentlyContinue
                    $result.Status = "Fixed"
                    $result.IsCompliant = $true
                    $result.Reason = "Process terminated."
                    $result.Actual = "Terminated"
                }
            }
            else {
                $result.Status = "Compliant"
                $result.IsCompliant = $true
                $result.Reason = "Process is not running."
            }
        }
        elseif ($Rule.State -eq "Present") {
            if (-not $isRunning) {
                $result.Status = "Non-Compliant"
                $result.Reason = "Process '$($Rule.Name)' is NOT running (Required)."
                # Enforce start? Maybe later.
            }
            else {
                $result.Status = "Compliant"
                $result.IsCompliant = $true
            }
        }

    }
    catch {
        $result.Status = "Error"
        $result.Reason = "Provider Error: $_"
    }

    return $result
}

Export-ModuleMember -Function Invoke-ThemisProcessRule
