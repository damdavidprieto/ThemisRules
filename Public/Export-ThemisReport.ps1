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

    .PARAMETER Title
        Title of the HTML report. Defaults to "ThemisRules report".

    .PARAMETER Language
        Language of the HTML page (the lang attribute), such as es or es-ES. Defaults to en.

    .PARAMETER Labels
        Texts of the HTML report in another language, by key: Policy, Generated, Compliance, Of, Rules, Excepted,
        Weighted, NotCompliant, and the header of each column (ID, Type, Name, MacroLevel, Severity, Status, Reason, or
        the name of an extra column). Keys you leave out keep the English text.

    .PARAMETER ValueLabels
        How to show Status and Severity values in the HTML report, for example @{ Compliant = 'Cumple'; High = 'Alta' }.
        The value itself is still used for the colours.

    .PARAMETER Columns
        The columns of the HTML table, in order: any property of the results, also ones you added (an explanation,
        how to fix it, a category). Defaults to ID, Type, Name, MacroLevel, Severity, Status and Reason.
    .EXAMPLE
        Invoke-ThemisPolicy -PolicyPath .\baseline.json | Export-ThemisReport -Path .\report.html

        Audits the policy and saves an HTML report.

    .EXAMPLE
        $results = Invoke-ThemisPolicy -PolicyPath .\baseline.json -MacroLevel L1
        Export-ThemisReport -InputObject $results -Path .\l1.csv

        Saves the L1 results as CSV, one row per rule.

    .EXAMPLE
        $results | ForEach-Object { $_ | Add-Member Category 'Red' -PassThru } |
            Export-ThemisReport -Path .\informe.html -Title 'Informe de seguridad' -Language es -Columns ID, Category, Name, Status, Reason `
                -Labels @{ Compliance = 'Cumplimiento'; Of = 'de'; Rules = 'reglas'; Name = 'Regla'; Category = 'Zona'; Status = 'Estado'; Reason = 'Motivo' } `
                -ValueLabels @{ Compliant = 'Cumple'; 'Non-Compliant' = 'No cumple' }

        Writes the report in Spanish, with a column of your own.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Labels and ValueLabels are used inside the script blocks that build the HTML.')]
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [ValidateSet('Json', 'Csv', 'Html')]
        [string]$Format,

        [string]$Title = 'ThemisRules report',

        [ValidatePattern('^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$')]
        [string]$Language = 'en',

        [hashtable]$Labels = @{},

        [hashtable]$ValueLabels = @{},

        [ValidateNotNullOrEmpty()]
        [string[]]$Columns = @('ID', 'Type', 'Name', 'MacroLevel', 'Severity', 'Status', 'Reason')
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
                # Every value is encoded, also titles and labels: nothing from the system or the caller becomes markup.
                $encode = { param($value) [System.Net.WebUtility]::HtmlEncode("$(@($value) -join ', ')") }
                $english = @{
                    Policy = 'Policy'; Generated = 'Generated'; Compliance = 'Compliance'; Of = 'of'; Rules = 'rules'; Excepted = 'excepted'
                    Weighted = 'Weighted by severity'; NotCompliant = 'Not compliant'; MacroLevel = 'Level'
                }
                $label = { param($key) if ($Labels.ContainsKey($key)) { "$($Labels[$key])" } elseif ($english.ContainsKey($key)) { $english[$key] } else { $key } }
                $show = { param($value) if ($null -ne $value -and $ValueLabels.ContainsKey("$value")) { "$($ValueLabels["$value"])" } else { $value } }
                $statusColumn = [array]::IndexOf([string[]]$Columns, 'Status') + 1
                $header = ($Columns | ForEach-Object { "<th>$(& $encode (& $label $_))</th>" }) -join ''
                $rows = foreach ($r in $results) {
                    $class = if ($r.Status -eq 'Excepted') { 'exc' } elseif ($r.IsCompliant) { 'ok' } else { 'fail' }
                    $cells = foreach ($column in $Columns) {
                        $value = if ($r.PSObject.Properties[$column]) { $r.$column } else { $null }
                        if ($column -in 'Status', 'Severity') { $value = & $show $value }
                        "<td>$(& $encode $value)</td>"
                    }
                    "<tr class='$class'>$($cells -join '')</tr>"
                }
                $policyNames = & $encode ($summary.Policies -join ', ')
                $color = if ($statusColumn -gt 0) { "tr.ok td:nth-child($statusColumn){color:#1a7f37}tr.fail td:nth-child($statusColumn){color:#cf222e}tr.exc td:nth-child($statusColumn){color:#9a6700}" } else { '' }
                $severities = ($bySeverity.Keys | ForEach-Object { "$($bySeverity[$_]) $(& $show $_)" }) -join ', '
                $excepted = if ($summary.Excepted) { ", $($summary.Excepted) $(& $label 'Excepted')" } else { '' }
                @"
<!DOCTYPE html>
<html lang="$Language"><head><meta charset="utf-8"><title>$(& $encode $Title)</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ccc;padding:6px;text-align:left}$color</style>
</head><body>
<h1>$(& $encode $Title)</h1>
<p>$(& $encode (& $label 'Policy')): $policyNames<br>$(& $encode (& $label 'Generated')): $($summary.Generated)<br>
$(& $encode (& $label 'Compliance')): <strong>$($summary.Score)%</strong> ($compliant $(& $encode (& $label 'Of')) $($counted.Count) $(& $encode (& $label 'Rules'))$(& $encode $excepted))<br>
$(& $encode (& $label 'Weighted')): <strong>$($summary.WeightedScore)%</strong><br>
$(& $encode (& $label 'NotCompliant')): $(& $encode $severities)</p>
<table><thead><tr>$header</tr></thead>
<tbody>
$($rows -join "`n")
</tbody></table></body></html>
"@ | Set-Content -Path $Path -Encoding UTF8
            }
        }

        Get-Item -Path $Path
    }
}
