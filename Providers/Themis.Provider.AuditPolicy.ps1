# ThemisRules AuditPolicy provider: Advanced Audit Policy subcategories (auditpol).
#
# Rules name the subcategory by GUID, because subcategory names depend on the Windows display
# language. Setting is what must be audited: Success, Failure, SuccessAndFailure or NoAuditing.
# Auditing more than required (for example Success and Failure when Success is required) is
# compliant; Enforce adds what is missing and keeps what is already enabled.

function Invoke-ThemisAuditPolicyRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null }
    $names = @{ 0 = 'NoAuditing'; 1 = 'Success'; 2 = 'Failure'; 3 = 'SuccessAndFailure' }
    $required = @{ 'NoAuditing' = 0; 'Success' = 1; 'Failure' = 2; 'SuccessAndFailure' = 3 }

    $subcategory = "$($Rule.Subcategory)".ToUpperInvariant()
    if ($subcategory -notmatch '^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$') {
        $result.Status = 'Error'
        $result.Reason = "Subcategory must be a GUID in braces, for example {0CCE9215-69AE-11D9-BED3-505054503030}: '$($Rule.Subcategory)'."
        return $result
    }
    if (-not $required.ContainsKey("$($Rule.Setting)")) {
        $result.Status = 'Error'
        $result.Reason = "Setting must be Success, Failure, SuccessAndFailure or NoAuditing: '$($Rule.Setting)'."
        return $result
    }
    if (-not (Test-ThemisElevated)) {
        $result.Status = 'Error'
        $result.Reason = 'Reading the audit policy requires an elevated session (Run as administrator).'
        return $result
    }

    try {
        $wanted = $required["$($Rule.Setting)"]
        $settings = Get-ThemisAuditPolicySetting
        if (-not $settings.ContainsKey($subcategory)) {
            $result.Status = 'Error'
            $result.Reason = "Subcategory $subcategory does not exist on this system."
            return $result
        }

        $current = [int]$settings[$subcategory]
        $result.Actual = $names[$current]
        $compliant = if ($wanted -eq 0) { $current -eq 0 } else { ($current -band $wanted) -eq $wanted }

        if ($compliant) {
            $result.Status = 'Compliant'
            $result.IsCompliant = $true
            $result.Reason = "Audits $($names[$current]) (required: $($Rule.Setting))."
            return $result
        }

        $result.Status = 'Non-Compliant'
        $result.Reason = "Audits $($names[$current]); required: $($Rule.Setting)."

        if ($Mode -eq 'Enforce') {
            $target = if ($wanted -eq 0) { 0 } else { $current -bor $wanted }
            Set-ThemisAuditPolicySetting -Subcategory $subcategory -Success (($target -band 1) -eq 1) -Failure (($target -band 2) -eq 2) -Confirm:$false
            $after = [int](Get-ThemisAuditPolicySetting)[$subcategory]
            if ($after -eq $target) {
                $result.Status = 'Fixed'
                $result.IsCompliant = $true
                $result.Reason = "Audit setting changed to $($names[$target])."
                $result.Actual = $names[$after]
            }
            else {
                $result.Status = 'EnforceFailed'
                $result.Reason = "Audit setting is still $($names[$after]); a Group Policy may override it."
            }
        }
    }
    catch {
        $result.Status = 'Error'
        $result.Reason = "Provider Error: $_"
    }

    return $result
}
