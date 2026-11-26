# ThemisRules: exceptions, accepted deviations from a policy.
#
# An exception names a rule by ID and says why it does not have to comply, and optionally until when and who
# accepted it. While it is valid, a rule that does not comply is Excepted instead of Non-Compliant, and Enforce
# leaves it as it is. An expired exception is ignored (with a warning), so the rule counts again.
#
#   ID      the rule ID (required)
#   Reason  why the deviation is accepted (required)
#   Until   last day it is valid, yyyy-MM-dd (optional)
#   Owner   who accepted it (optional)

# Statuses an exception covers: the rule was read and does not comply. Errors and unknown values are not hidden.
$script:ThemisExceptedStatuses = 'Non-Compliant', 'MissingKey', 'MissingValue', 'MissingService', 'Manual'

function Get-ThemisExceptionMap {
    <#
    .SYNOPSIS
        The valid exceptions by rule ID, from a file or from objects. Writes a warning for expired ones and for IDs
        the policy does not have.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param($Exceptions, [string[]]$RuleIds = @(), [datetime]$Now = (Get-Date))

    $map = @{}
    if ($null -eq $Exceptions) { return $map }
    $items = $Exceptions
    if ($Exceptions -is [string]) {
        if (-not (Test-Path -LiteralPath $Exceptions -PathType Leaf)) { throw "Exceptions file not found: $Exceptions" }
        $items = Get-Content -LiteralPath $Exceptions -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($items.PSObject.Properties['Exceptions']) { $items = $items.Exceptions }
    }
    foreach ($item in @($items | Where-Object { $_ })) {
        $entry = if ($item -is [System.Collections.IDictionary]) { [pscustomobject]$item } else { $item }
        $id = "$($entry.ID)"
        if (-not $id -or [string]::IsNullOrWhiteSpace("$($entry.Reason)")) { throw "Every exception needs an ID and a Reason: $($entry | ConvertTo-Json -Compress)" }
        $until = $null
        if ($entry.Until) {
            $parsed = [datetime]::MinValue
            if (-not [datetime]::TryParseExact("$($entry.Until)", 'yyyy-MM-dd', [cultureinfo]::InvariantCulture, 'None', [ref]$parsed)) { throw "Exception $id has an Until that is not a date (yyyy-MM-dd): $($entry.Until)" }
            $until = $parsed
            # Valid through the whole last day.
            if ($Now -ge $until.AddDays(1)) {
                Write-Warning "[Themis] The exception for $id expired on $($entry.Until); the rule counts again."
                continue
            }
        }
        if ($RuleIds.Count -and $RuleIds -notcontains $id) { Write-Warning "[Themis] The exception for $id names a rule the policy does not have." }
        $map[$id] = [pscustomobject]@{ ID = $id; Reason = "$($entry.Reason)"; Until = $(if ($until) { $until.ToString('yyyy-MM-dd') } else { $null }); Owner = $(if ($entry.Owner) { "$($entry.Owner)" } else { $null }) }
    }
    return $map
}
