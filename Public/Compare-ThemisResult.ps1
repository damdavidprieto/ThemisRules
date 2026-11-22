function Compare-ThemisResult {
    <#
    .SYNOPSIS
        Compares two runs of the same policy and returns the rules whose compliance changed.

    .DESCRIPTION
        Pass the results of an earlier run (for example the Enforce run, or an audit saved as JSON) and those of
        a later audit. Each rule whose IsCompliant differs is returned with ID, Type, Name, Change ('Drifted' when
        it was compliant and no longer is, 'Fixed' when it was not and now is), Before and After (the status in
        each run) and Reason (from the later run). Rules that are only in one of the runs are reported with Change
        'Added' or 'Removed'. Use it to see what someone or something changed after you applied a policy.

    .PARAMETER Reference
        Results of the earlier run.

    .PARAMETER Difference
        Results of the later run.

    .EXAMPLE
        $applied = Invoke-ThemisPolicy -PolicyPath .\baseline.json -Mode Enforce
        Compare-ThemisResult -Reference $applied -Difference (Invoke-ThemisPolicy -PolicyPath .\baseline.json) |
            Where-Object Change -eq 'Drifted'

        Lists the rules that were applied and have since been changed back.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Reference,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Difference
    )

    $before = @{}
    foreach ($r in @($Reference | Where-Object { $_ })) { $before["$($r.ID)"] = $r }
    $seen = @{}
    foreach ($r in @($Difference | Where-Object { $_ })) {
        $id = "$($r.ID)"
        $seen[$id] = $true
        $old = $before[$id]
        $change = $null
        if (-not $old) { $change = 'Added' }
        elseif ([bool]$old.IsCompliant -and -not [bool]$r.IsCompliant) { $change = 'Drifted' }
        elseif (-not [bool]$old.IsCompliant -and [bool]$r.IsCompliant) { $change = 'Fixed' }
        if ($change) {
            [pscustomobject]@{ ID = $id; Type = $r.Type; Name = $r.Name; Change = $change; Before = $(if ($old) { $old.Status }); After = $r.Status; Reason = $r.Reason }
        }
    }
    foreach ($id in $before.Keys | Sort-Object) {
        if ($seen.ContainsKey($id)) { continue }
        $old = $before[$id]
        [pscustomobject]@{ ID = $id; Type = $old.Type; Name = $old.Name; Change = 'Removed'; Before = $old.Status; After = $null; Reason = '' }
    }
}
