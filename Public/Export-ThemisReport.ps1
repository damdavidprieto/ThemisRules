function Export-ThemisReport {
    <#
    .SYNOPSIS
        Saves Invoke-ThemisPolicy results as a JSON, CSV or HTML report.
    .DESCRIPTION
        The format comes from -Format or, if omitted, from the file extension (.json, .csv,
        .html/.htm). JSON and HTML reports include a summary with the number of rules, how
        many comply, how many are Excepted, the compliance score (Excepted rules left out), a
        score weighted by Severity (Low 1, Medium 2, High 3, Critical 4) and the rules that do not
        comply by Severity. The HTML report encodes every value, so data from the system cannot
        inject markup. Returns the report file.
    .PARAMETER InputObject
        Results from Invoke-ThemisPolicy (accepts pipeline input).
    .PARAMETER Path
        Output file.
    .PARAMETER Format
        Json, Csv or Html.
    .EXAMPLE
        Invoke-ThemisPolicy -PolicyPath .\baseline.json | Export-ThemisReport -Path .\report.html

        Audits the policy and saves an HTML report.

    .EXAMPLE
        $results = Invoke-ThemisPolicy -PolicyPath .\baseline.json -MacroLevel L1
        Export-ThemisReport -InputObject $results -Path .\l1.csv

        Saves the L1 results as CSV, one row per rule.
    #>
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [ValidateSet('Json', 'Csv', 'Html')]
        [string]$Format
    )

    begin {
        $results = [System.Collections.Generic.List[object]]::new()
    }

    process {
        foreach ($item in $InputObject) { $results.Add($item) }
    }

    end {
        if (-not $Format) {
            $Format = switch -Regex ([IO.Path]::GetExtension($Path)) {
                '^\.json$' { 'Json' }
                '^\.csv$' { 'Csv' }
                '^\.html?$' { 'Html' }
                default { throw "Cannot infer the report format from '$Path'. Use -Format Json, Csv or Html." }
            }
        }

        $total = $results.Count
        # An accepted deviation is neither a pass nor a failure: it is left out of the scores.
        $counted = @($results | Where-Object { $_.Status -ne 'Excepted' })
        $compliant = @($counted | Where-Object IsCompliant).Count
        $weights = @{ Low = 1; Medium = 2; High = 3; Critical = 4 }
        $weightOf = { param($r) $w = $weights["$($r.Severity)"]; if ($w) { $w } else { 2 } }
        $all = 0; $passed = 0
        foreach ($r in $counted) { $w = & $weightOf $r; $all += $w; if ($r.IsCompliant) { $passed += $w } }
        $bySeverity = [ordered]@{}
        foreach ($level in 'Critical', 'High', 'Medium', 'Low') {
            $bySeverity[$level] = @($counted | Where-Object { -not $_.IsCompliant -and $(if ($_.Severity) { "$($_.Severity)" } else { 'Medium' }) -eq $level }).Count
        }
        $summary = [ordered]@{
            Generated     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            Policies      = @($results | Select-Object -ExpandProperty Policy -Unique)
            Total         = $total
            Compliant     = $compliant
            NonCompliant  = $counted.Count - $compliant
            Excepted      = $total - $counted.Count
            Score         = if ($counted.Count -gt 0) { [math]::Round(100 * $compliant / $counted.Count, 1) } else { 0 }
            WeightedScore = if ($all -gt 0) { [math]::Round(100 * $passed / $all, 1) } else { 0 }
            NonCompliantBySeverity = $bySeverity
        }

        $parent = Split-Path -Path $Path -Parent
        if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }

        switch ($Format) {
            'Json' {
                [ordered]@{ Summary = $summary; Results = $results } |
                    ConvertTo-Json -Depth 5 | Set-Content -Path $Path -Encoding UTF8
            }
            'Csv' {
                # Values that start with = + - @ or a tab/CR are read as formulas by spreadsheets
                # (CSV injection). Registry text can come from anyone who can write the value, so
                # such values get a leading apostrophe, the usual neutralisation.
                $safe = foreach ($r in $results) {
                    $copy = [ordered]@{}
                    foreach ($prop in $r.PSObject.Properties) {
                        $value = $prop.Value
                        if ($value -is [string] -and $value -match '^[=+\-@\t\r]') { $value = "'" + $value }
                        $copy[$prop.Name] = $value
                    }
                    [PSCustomObject]$copy
                }
                $safe | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
            }
            'Html' {
                $encode = { param($value) [System.Net.WebUtility]::HtmlEncode("$value") }
                $rows = foreach ($r in $results) {
                    $class = if ($r.Status -eq 'Excepted') { 'exc' } elseif ($r.IsCompliant) { 'ok' } else { 'fail' }
                    "<tr class='$class'><td>$(& $encode $r.ID)</td><td>$(& $encode $r.Type)</td><td>$(& $encode $r.Name)</td><td>$(& $encode $r.MacroLevel)</td><td>$(& $encode $r.Severity)</td><td>$(& $encode $r.Status)</td><td>$(& $encode $r.Reason)</td></tr>"
                }
                $policyNames = & $encode ($summary.Policies -join ', ')
                @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>ThemisRules report</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ccc;padding:6px;text-align:left}tr.ok td:nth-child(6){color:#1a7f37}tr.fail td:nth-child(6){color:#cf222e}tr.exc td:nth-child(6){color:#9a6700}</style>
</head><body>
<h1>ThemisRules report</h1>
<p>Policy: $policyNames<br>Generated: $($summary.Generated)<br>
Compliance: <strong>$($summary.Score)%</strong> ($compliant of $($counted.Count) rules$(if ($summary.Excepted) { ", $($summary.Excepted) excepted" }))<br>
Weighted by severity: <strong>$($summary.WeightedScore)%</strong><br>
Not compliant: $(($bySeverity.Keys | ForEach-Object { "$($bySeverity[$_]) $_" }) -join ', ')</p>
<table><thead><tr><th>ID</th><th>Type</th><th>Name</th><th>Level</th><th>Severity</th><th>Status</th><th>Reason</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody></table></body></html>
"@ | Set-Content -Path $Path -Encoding UTF8
            }
        }

        Get-Item -Path $Path
    }
}
