function Test-ThemisPolicy {
    <#
    .SYNOPSIS
        Checks a policy file against the policy schema and returns every problem found.

    .DESCRIPTION
        Reports, one object per problem (Section, ID, Problem): sections that no provider handles, rules without
        a required field, and fields that the schema does not know. An unknown field is usually a typo, such as
        "Vaule" for "Value": without this check the rule would run without it and do something else than meant.
        Fields starting with "_" are ignored (the engine adds them). Returns nothing when the policy is valid.
        Invoke-ThemisPolicy -Strict runs it first and refuses a policy with problems.

    .PARAMETER Path
        The policy file.

    .EXAMPLE
        Test-ThemisPolicy -Path .\baseline.json

        Lists the problems of the policy, if any.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Policy not found: $Path" }
    $policy = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    $schemaFile = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'Schema') 'ThemisPolicy.schema.json'
    $schema = Get-Content -LiteralPath $schemaFile -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($script:ProviderCache.Count -eq 0) { Initialize-ThemisProviders }

    foreach ($section in $policy.PSObject.Properties) {
        if ($section.Name -eq 'Meta') { continue }
        if ($section.Name -notmatch '^(.+)Rules$' -or -not $script:ProviderCache.ContainsKey($Matches[1])) {
            [pscustomobject]@{ Section = $section.Name; ID = $null; Problem = 'No provider handles this section: its rules would be skipped.' }
            continue
        }
        $definition = $schema.properties.($section.Name)
        $known = @(); $required = @()
        if ($definition -and $definition.items) {
            $known = @($definition.items.properties.PSObject.Properties.Name)
            $required = @($definition.items.required)
        }
        foreach ($rule in @($section.Value)) {
            $id = "$($rule.ID)"
            foreach ($field in $required) {
                # An empty list is a valid value (UserRights: nobody holds the right); a missing field is not.
                if ($null -eq $rule.PSObject.Properties[$field] -or ($null -eq $rule.$field)) {
                    [pscustomobject]@{ Section = $section.Name; ID = $id; Problem = "Required field $field is missing." }
                }
            }
            if (-not $known.Count) { continue }
            foreach ($field in $rule.PSObject.Properties.Name) {
                if ($field.StartsWith('_') -or $field -in $known) { continue }
                $hint = @($known | Where-Object { [string]::Equals($_, $field, 'OrdinalIgnoreCase') -or (Get-ThemisEditDistance $_ $field) -le 2 }) | Select-Object -First 1
                [pscustomobject]@{ Section = $section.Name; ID = $id; Problem = "Unknown field $field$(if ($hint) { " (did you mean ${hint}?)" })." }
            }
        }
    }
}
