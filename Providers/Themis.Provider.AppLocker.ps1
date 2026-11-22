# ThemisRules AppLocker provider: one AppLocker rule collection of the local policy.
#
#   Collection       Exe, Script, Msi, Dll or Appx.
#   Mode             AuditOnly (log what would be blocked), Enabled (block) or NotConfigured.
#   DefaultRules     Include the standard allow rules (default $true): everyone may run what is in the Windows
#                    and Program Files folders, administrators may run anything. Everything else, such as programs
#                    and scripts in Downloads, Temp or inside a .zip, is not allowed.
#   AllowPublishers  Publishers allowed anywhere, as AppLocker writes them (Get-AppLockerFileInformation shows
#                    them), for example 'O=ANTHROPIC, PBC, L=SAN FRANCISCO, S=CALIFORNIA, C=US'.
#   AllowPaths       Extra folders or files allowed, such as '%PROGRAMDATA%\MyTool\*'. Use only folders that users
#                    cannot write to, or the rule allows whatever they put there.
#   RestoreXml       Restore rules only: the exact collection to put back ('' = no collection).
# Themis owns the rules whose name starts with 'Themis: ' and leaves the others in the collection as they are.
# Start with AuditOnly: Windows logs in Microsoft-Windows-AppLocker/* what would have been blocked, without blocking
# it. AppLocker only acts while the Application Identity service (AppIDSvc) runs. Changing the policy needs an
# elevated session.

$script:ThemisAppLockerPrefix = 'Themis: '

function Get-ThemisAppLockerPolicyXml {
    <#
    .SYNOPSIS
        The local AppLocker policy as XML text. Separate so the tests can mock it.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', '', Justification = 'The AppLocker module ships with Windows client editions; the provider only runs there.')]
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return "$(Get-AppLockerPolicy -Local -Xml -ErrorAction Stop)"
}

function Set-ThemisAppLockerPolicyXml {
    <#
    .SYNOPSIS
        Replaces the local AppLocker policy with the given XML.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', '', Justification = 'The AppLocker module ships with Windows client editions; the provider only runs there.')]
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Xml)

    if (-not $PSCmdlet.ShouldProcess('local AppLocker policy', 'Replace')) { return }
    $file = Join-Path ([System.IO.Path]::GetTempPath()) ("themis-applocker-{0}.xml" -f [guid]::NewGuid().ToString('N'))
    try {
        [System.IO.File]::WriteAllText($file, $Xml, (New-Object System.Text.UTF8Encoding($false)))
        Set-AppLockerPolicy -XmlPolicy $file -ErrorAction Stop
    }
    finally { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
}

function Get-ThemisAppIdServiceStatus {
    <#
    .SYNOPSIS
        Status of the Application Identity service, which AppLocker needs. Separate so the tests can mock it.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return "$((Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue).Status)"
}

function Get-ThemisAppLockerId {
    <#
    .SYNOPSIS
        A rule Id derived from the rule itself: a changed rule gets a new Id, so comparing Ids compares rules.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Text)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try { return ([guid]::new($md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)))).ToString() }
    finally { $md5.Dispose() }
}

function Get-ThemisAppLockerRuleSet {
    <#
    .SYNOPSIS
        The rules Themis wants in a collection, as XML elements (strings), for a rule definition.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory = $true)][string]$Collection, [bool]$DefaultRules = $true, [string[]]$AllowPublishers = @(), [string[]]$AllowPaths = @())

    $enc = { param($s) [System.Security.SecurityElement]::Escape("$s") }
    $rules = [System.Collections.Generic.List[string]]::new()
    $pathRule = {
        param($name, $sid, $path)
        $id = Get-ThemisAppLockerId "$Collection|path|$sid|$path"
        $rules.Add("<FilePathRule Id=`"$id`" Name=`"$(& $enc ($script:ThemisAppLockerPrefix + $name))`" Description=`"`" UserOrGroupSid=`"$sid`" Action=`"Allow`"><Conditions><FilePathCondition Path=`"$(& $enc $path)`" /></Conditions></FilePathRule>")
    }
    $publisherRule = {
        param($name, $sid, $publisher)
        $id = Get-ThemisAppLockerId "$Collection|publisher|$sid|$publisher"
        $rules.Add("<FilePublisherRule Id=`"$id`" Name=`"$(& $enc ($script:ThemisAppLockerPrefix + $name))`" Description=`"`" UserOrGroupSid=`"$sid`" Action=`"Allow`"><Conditions><FilePublisherCondition PublisherName=`"$(& $enc $publisher)`" ProductName=`"*`" BinaryName=`"*`"><BinaryVersionRange LowSection=`"*`" HighSection=`"*`" /></FilePublisherCondition></Conditions></FilePublisherRule>")
    }
    if ($DefaultRules) {
        switch ($Collection) {
            'Msi' {
                & $pathRule 'Windows Installer folder' 'S-1-1-0' '%WINDIR%\Installer\*'
                & $pathRule 'Administrators' 'S-1-5-32-544' '*.*'
            }
            'Appx' { & $publisherRule 'Signed packaged apps' 'S-1-1-0' '*' }
            default {
                & $pathRule 'Windows folder' 'S-1-1-0' '%WINDIR%\*'
                & $pathRule 'Program Files' 'S-1-1-0' '%PROGRAMFILES%\*'
                & $pathRule 'Administrators' 'S-1-5-32-544' '*'
            }
        }
    }
    foreach ($p in @($AllowPublishers | Where-Object { $_ })) { & $publisherRule "Publisher $p" 'S-1-1-0' $p }
    foreach ($p in @($AllowPaths | Where-Object { $_ })) { & $pathRule "Path $p" 'S-1-1-0' $p }
    return @($rules)
}

function Invoke-ThemisAppLockerRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null }
    $collection = "$($Rule.Collection)"
    $isRestore = $null -ne $Rule.PSObject.Properties['RestoreXml']
    $wantedMode = if ($Rule.Mode) { "$($Rule.Mode)" } else { 'AuditOnly' }
    $problem = $null
    if ($collection -notin 'Exe', 'Script', 'Msi', 'Dll', 'Appx') { $problem = "Collection must be Exe, Script, Msi, Dll or Appx: '$collection'." }
    elseif (-not $isRestore -and $wantedMode -notin 'AuditOnly', 'Enabled', 'NotConfigured') { $problem = "Mode must be AuditOnly, Enabled or NotConfigured: '$wantedMode'." }
    elseif ($isRestore -and $Rule.RestoreXml -and "$($Rule.RestoreXml)" -notmatch "^<RuleCollection Type=`"$collection`"") { $problem = "RestoreXml must be a RuleCollection of type $collection." }
    if ($problem) { $result.Status = 'Error'; $result.Reason = $problem; return $result }

    try {
        $doc = [xml](Get-ThemisAppLockerPolicyXml)
        if (-not $doc.DocumentElement) { $doc = [xml]'<AppLockerPolicy Version="1" />' }
        $node = @($doc.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq 'RuleCollection' -and $_.GetAttribute('Type') -eq $collection }) | Select-Object -First 1
        $currentMode = if ($node) { "$($node.GetAttribute('EnforcementMode'))" } else { 'NotConfigured' }
        $currentXml = if ($node) { $node.OuterXml } else { '' }
        $service = Get-ThemisAppIdServiceStatus
        $result.Actual = $currentMode
        $result.Data = @{ Mode = $currentMode; Rules = @(if ($node) { @($node.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] } | ForEach-Object { $_.GetAttribute('Name') }) }); ServiceStatus = $service }
        $serviceNote = if ($service -ne 'Running') { " AppLocker only acts while the Application Identity service (AppIDSvc) runs; it is $(if ($service) { $service } else { 'missing' })." } else { '' }

        if ($isRestore) {
            $compliant = ($currentXml -replace '\s+', ' ') -eq ("$($Rule.RestoreXml)" -replace '\s+', ' ')
            $wanted = $null
        }
        else {
            $wanted = @(Get-ThemisAppLockerRuleSet -Collection $collection -DefaultRules ($null -eq $Rule.DefaultRules -or [bool]$Rule.DefaultRules) -AllowPublishers @($Rule.AllowPublishers) -AllowPaths @($Rule.AllowPaths))
            $haveIds = @(if ($node) { @($node.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] } | ForEach-Object { $_.GetAttribute('Id') }) })
            $wantIds = @($wanted | ForEach-Object { ([xml]$_).DocumentElement.GetAttribute('Id') })
            $ownIds = @(if ($node) { @($node.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] -and $_.GetAttribute('Name').StartsWith($script:ThemisAppLockerPrefix) } | ForEach-Object { $_.GetAttribute('Id') }) })
            $compliant = if ($wantedMode -eq 'NotConfigured') { $currentMode -eq 'NotConfigured' }
            else { $currentMode -eq $wantedMode -and -not @($wantIds | Where-Object { $haveIds -notcontains $_ }).Count -and -not @($ownIds | Where-Object { $wantIds -notcontains $_ }).Count }
        }
        if ($compliant) {
            $result.Status = 'Compliant'
            $result.IsCompliant = $true
            $result.Reason = "AppLocker $collection rules are $currentMode.$serviceNote"
            return $result
        }
        $result.Status = 'Non-Compliant'
        $result.Reason = if ($isRestore) { "AppLocker $collection rules differ from the saved ones." } else { "AppLocker $collection rules are $currentMode; required: $wantedMode with the Themis rules.$serviceNote" }
        if ($Mode -ne 'Enforce') { return $result }
        if (-not (Test-ThemisElevated)) {
            $result.Status = 'NeedsElevation'
            $result.Reason = 'Changing the AppLocker policy requires an elevated session (Run as administrator).'
            return $result
        }

        # The new collection: the rules of others as they are, Themis' own rules as wanted.
        if ($node) { $null = $doc.DocumentElement.RemoveChild($node) }
        if ($isRestore) {
            if ($Rule.RestoreXml) {
                $fragment = $doc.CreateDocumentFragment(); $fragment.InnerXml = "$($Rule.RestoreXml)"
                $null = $doc.DocumentElement.AppendChild($fragment)
            }
        }
        elseif ($wantedMode -ne 'NotConfigured') {
            $new = $doc.CreateElement('RuleCollection')
            $new.SetAttribute('Type', $collection)
            $new.SetAttribute('EnforcementMode', $wantedMode)
            if ($node) { foreach ($child in @($node.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] -and -not $_.GetAttribute('Name').StartsWith($script:ThemisAppLockerPrefix) })) { $null = $new.AppendChild($doc.ImportNode($child, $true)) } }
            foreach ($r in $wanted) { $fragment = $doc.CreateDocumentFragment(); $fragment.InnerXml = $r; $null = $new.AppendChild($fragment) }
            $null = $doc.DocumentElement.AppendChild($new)
        }
        Set-ThemisAppLockerPolicyXml -Xml $doc.OuterXml -Confirm:$false

        $after = [xml](Get-ThemisAppLockerPolicyXml)
        $afterNode = @($after.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq 'RuleCollection' -and $_.GetAttribute('Type') -eq $collection }) | Select-Object -First 1
        $afterMode = if ($afterNode) { "$($afterNode.GetAttribute('EnforcementMode'))" } else { 'NotConfigured' }
        $expectedMode = if ($isRestore) { if ($Rule.RestoreXml) { ([xml]"$($Rule.RestoreXml)").DocumentElement.GetAttribute('EnforcementMode') } else { 'NotConfigured' } } else { $wantedMode }
        if ($afterMode -ne $expectedMode) {
            $result.Status = 'EnforceFailed'
            $result.Reason = "AppLocker $collection rules are still $afterMode."
            return $result
        }
        $result.Actual = $afterMode
        $result.Previous = [ordered]@{ Collection = $collection; RestoreXml = $currentXml }
        $result.Status = 'Fixed'
        $result.IsCompliant = $true
        $result.Reason = "AppLocker $collection rules are now $afterMode.$serviceNote"
    }
    catch {
        $result.Status = 'Error'
        $result.Reason = "Provider Error: $_"
    }
    return $result
}
