<#
.SYNOPSIS
    Themis Service Provider
.DESCRIPTION
    Handles 'Service' type rules.
    Actions supported: Check (State), Ensure (Running/Stopped), Startup (Auto/Manual/Disabled).
#>

function Invoke-ThemisServiceRule {
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
            if ($Rule.Action -eq "Absent") {
                $result.Status = "Compliant"
                $result.IsCompliant = $true
                $result.Reason = "Service is absent as expected."
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
        $compliant = $true
        $reasons = @()

        # Check Startup Type
        if ($Rule.StartupType) {
            if ($svc.StartType -ne $Rule.StartupType) {
                $compliant = $false
                $reasons += "Startup mismatch (Expected: $($Rule.StartupType), Actual: $($svc.StartType))."
                
                if ($Mode -eq "Enforce") {
                    Set-Service -Name $svc.Name -StartupType $Rule.StartupType -ErrorAction Stop
                    $reasons += "[Fixed] Startup type set to $($Rule.StartupType)."
                }
            }
        }

        # Check State
        if ($Rule.State) {
            if ($svc.Status -ne $Rule.State) {
                $compliant = $false
                $reasons += "State mismatch (Expected: $($Rule.State), Actual: $($svc.Status))."
                
                if ($Mode -eq "Enforce") {
                    if ($Rule.State -eq "Running") { Start-Service -Name $svc.Name -ErrorAction Stop }
                    elseif ($Rule.State -eq "Stopped") { Stop-Service -Name $svc.Name -Force -ErrorAction Stop }
                    else { throw "Unsupported service State '$($Rule.State)'. Use Running or Stopped." }
                    $reasons += "[Fixed] Service state changed to $($Rule.State)."
                }
            }
        }
        
        # Check Action: Absent (Removal)
        if ($Rule.Action -eq "Absent") {
            $compliant = $false
            $reasons += "Service exists but should be absent."
            if ($Mode -eq "Enforce") {
                # Requires external tool usually, sc.exe
                Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                $null = & sc.exe delete $svc.Name
                if ($LASTEXITCODE -ne 0) { throw "sc.exe delete '$($svc.Name)' failed with exit code $LASTEXITCODE." }
                $reasons += "[Fixed] Service deleted via SC."
            }
        }


        # Finalize
        if ($reasons.Count -gt 0) {
            # Recalculate compliance if enforcement happened
            if ($Mode -eq "Enforce") {
                # Assume strictly fixed for now if no exception thrown
                $result.IsCompliant = $true
                $result.Status = "Fixed"
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
        $svc.Refresh()
        $result.Actual = "$($svc.Status) ($($svc.StartType))"

    }
    catch {
        $result.Status = "Error"
        $result.Reason = "Provider Error: $_"
    }

    return $result
}

