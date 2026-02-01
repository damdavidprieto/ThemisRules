<#
.SYNOPSIS
    Themis Registry Provider
.DESCRIPTION
    Handles 'Registry' type rules for Themis Engine.
#>

function Invoke-ThemisRegistryRule {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode # Audit, Enforce
    )

    $result = [ordered]@{
        Status      = "Unknown"
        IsCompliant = $false
        Reason      = ""
        Actual      = $null
    }

    try {
        if (-not (Test-Path $Rule.Path)) {
            $result.Status = "MissingKey"
            $result.Reason = "Key path not found: $($Rule.Path)"
            
            if ($Mode -eq "Enforce") {
                New-Item -Path $Rule.Path -Force | Out-Null
                # Re-evaluate after creation if value is needed, or just continue
            }
            else {
                return $result
            }
        }

        $reg = Get-ItemProperty -Path $Rule.Path -Name $Rule.ValueName -ErrorAction SilentlyContinue
        
        if ($null -eq $reg) {
            $result.Status = "MissingValue"
            $result.Reason = "Value '$($Rule.ValueName)' not found."
        }
        else {
            $currentValue = $reg.$($Rule.ValueName)
            $result.Actual = $currentValue

            $match = $false
            # Enhanced Type handling
            switch ($Rule.Type) {
                "DWord" { if ([long]$currentValue -eq [long]$Rule.Value) { $match = $true } }
                "QWord" { if ([long]$currentValue -eq [long]$Rule.Value) { $match = $true } }
                "String" { if ("$currentValue" -eq "$($Rule.Value)") { $match = $true } }
                "MultiString" { 
                    # Compare arrays
                    if ($null -ne $currentValue -and ($currentValue | Sort-Object) -join ',' -eq ($Rule.Value | Sort-Object) -join ',') { 
                        $match = $true 
                    } 
                }
                Default { if ("$currentValue" -eq "$($Rule.Value)") { $match = $true } } # Fallback
            }

            if ($match) {
                $result.Status = "Compliant"
                $result.IsCompliant = $true
                $result.Reason = "Value matches expected configuration."
            }
            else {
                $result.Status = "Non-Compliant"
                $result.Reason = "Expected '$($Rule.Value)' but found '$currentValue'."
            }
        }

        # ENFORCEMENT
        if ($Mode -eq "Enforce" -and -not $result.IsCompliant) {
            try {
                Set-ItemProperty -Path $Rule.Path -Name $Rule.ValueName -Value $Rule.Value -Type ($Rule.Type ?? "String") -Force -ErrorAction Stop
                $result.Status = "Fixed"
                $result.IsCompliant = $true
                $result.Reason = "Remediated by Registry Provider."
            }
            catch {
                $result.Status = "EnforceFailed"
                $result.Reason = "Failed to set value: $_"
            }
        }

    }
    catch {
        $result.Status = "Error"
        $result.Reason = "Provider Error: $_"
    }

    return $result
}

Export-ModuleMember -Function Invoke-ThemisRegistryRule
