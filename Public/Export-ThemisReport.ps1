function Export-ThemisReport {
    <#
    .SYNOPSIS
        Saves Invoke-ThemisPolicy results as a JSON, CSV or HTML report.
    .DESCRIPTION
        The format comes from -Format or, if omitted, from the file extension (.json, .csv,
        .html/.htm). JSON and HTML reports include a summary with the compliance score.
    .PARAMETER InputObject
        Results from Invoke-ThemisPolicy (accepts pipeline input).
    .PARAMETER Path
        Output file.
    .PARAMETER Format
        Json, Csv or Html.
    .EXAMPLE
        Invoke-ThemisPolicy -PolicyPath .\baseline.json | Export-ThemisReport -Path .\report.html
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [ValidateSet('Json', 'Csv', 'Html')]
        [string]$Format
    )

    begin {
        $results = New-Object System.Collections.Generic.List[object]
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
        $compliant = @($results | Where-Object IsCompliant).Count
        $summary = [ordered]@{
            Generated    = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            Policies     = @($results | Select-Object -ExpandProperty Policy -Unique)
            Total        = $total
            Compliant    = $compliant
            NonCompliant = $total - $compliant
            Score        = if ($total -gt 0) { [math]::Round(100 * $compliant / $total, 1) } else { 0 }
        }

        $parent = Split-Path -Path $Path -Parent
        if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }

        switch ($Format) {
            'Json' {
                [ordered]@{ Summary = $summary; Results = $results } |
                    ConvertTo-Json -Depth 5 | Set-Content -Path $Path -Encoding UTF8
            }
            'Csv' {
                $results | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
            }
            'Html' {
                $encode = { param($value) [System.Net.WebUtility]::HtmlEncode("$value") }
                $rows = foreach ($r in $results) {
                    $class = if ($r.IsCompliant) { 'ok' } else { 'fail' }
                    "<tr class='$class'><td>$(& $encode $r.ID)</td><td>$(& $encode $r.Type)</td><td>$(& $encode $r.Name)</td><td>$(& $encode $r.MacroLevel)</td><td>$(& $encode $r.Status)</td><td>$(& $encode $r.Reason)</td></tr>"
                }
                $policyNames = & $encode ($summary.Policies -join ', ')
                @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>ThemisRules report</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ccc;padding:6px;text-align:left}tr.ok td:nth-child(5){color:#1a7f37}tr.fail td:nth-child(5){color:#cf222e}</style>
</head><body>
<h1>ThemisRules report</h1>
<p>Policy: $policyNames<br>Generated: $($summary.Generated)<br>
Compliance: <strong>$($summary.Score)%</strong> ($compliant of $total rules)</p>
<table><thead><tr><th>ID</th><th>Type</th><th>Name</th><th>Level</th><th>Status</th><th>Reason</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody></table></body></html>
"@ | Set-Content -Path $Path -Encoding UTF8
            }
        }

        Get-Item -Path $Path
    }
}
