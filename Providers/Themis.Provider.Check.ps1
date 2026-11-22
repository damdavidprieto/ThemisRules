# ThemisRules Check provider: a condition someone has to fix by hand, such as Secure Boot in the
# firmware or BitLocker. Enforce never changes anything.
#
#   Fact       Name of a fact passed with -Facts, for example SecureBootOn.
#   Expected   The value the fact must have.
#   Action     What has to be done, in a sentence (shown in Reason when the check is not met).
# A check that is not met is Manual; one whose fact was not given is Unknown.

function Invoke-ThemisCheckRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $null = $Mode   # Checks are the same in both modes: they are never applied.
    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null }
    if ([string]::IsNullOrWhiteSpace("$($Rule.Fact)")) {
        $result.Status = 'Error'
        $result.Reason = 'Check rule has no Fact.'
        return $result
    }

    $actual = Get-ThemisFactValue -Facts $script:ThemisFacts -Name "$($Rule.Fact)"
    $result.Actual = $actual
    $result.Data = @{ Fact = "$($Rule.Fact)"; Value = $actual }
    if ($null -eq $actual) {
        $result.Reason = "The fact $($Rule.Fact) was not given (pass it with -Facts)."
        return $result
    }
    $match = if ($Rule.Expected -is [bool]) { [bool]$actual -eq $Rule.Expected } else { (Test-ThemisValue -Actual $actual -Rule ([pscustomobject]@{ Value = $Rule.Expected })).Match }
    if ($match) {
        $result.Status = 'Compliant'
        $result.IsCompliant = $true
        $result.Reason = "$($Rule.Fact) is $actual."
    }
    else {
        $result.Status = 'Manual'
        $result.Reason = if ($Rule.Action) { "$($Rule.Action) ($($Rule.Fact) is $actual)." } else { "$($Rule.Fact) is $actual; required: $($Rule.Expected). Fix it by hand." }
    }
    return $result
}
