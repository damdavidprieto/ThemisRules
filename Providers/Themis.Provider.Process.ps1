# Themis Process Provider
# Handles 'Process' type rules.
# Audits if a process is running. Enforce = Stop-Process.

function Invoke-ThemisProcessRule {
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

    # Get-Process and Stop-Process treat the name as a wildcard pattern: a rule named "*"
    # would match, and in Enforce mode stop, every process. Only exact names are allowed.
    if ([string]::IsNullOrWhiteSpace($Rule.Name) -or [System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($Rule.Name)) {
        $result.Status = "Error"
        $result.Reason = "Process rule needs an exact process name without wildcards: '$($Rule.Name)'."
        return $result
    }

    try {
        $procs = @(Get-Process -Name $Rule.Name -ErrorAction SilentlyContinue)

        $isRunning = ($procs.Count -gt 0)
        $result.Actual = if ($isRunning) { "Running ($($procs.Count))" } else { "Not Running" }

        if ($Rule.State -eq "Absent") {
            if ($isRunning) {
                $result.Status = "Non-Compliant"
                $result.Reason = "Process '$($Rule.Name)' is running (Blacklisted)."

                if ($Mode -eq "Enforce") {
                    $procs | Stop-Process -Force -ErrorAction SilentlyContinue
                    if (@(Get-Process -Name $Rule.Name -ErrorAction SilentlyContinue).Count -eq 0) {
                        $result.Status = "Fixed"
                        $result.IsCompliant = $true
                        $result.Reason = "Process terminated."
                        $result.Actual = "Terminated"
                    }
                    else {
                        $result.Status = "EnforceFailed"
                        $result.Reason = "Could not terminate every '$($Rule.Name)' process."
                    }
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
