# ThemisRules LocalGroupMember provider: direct membership of an account in a local group.
#
#   Group    SID of the local group, for example S-1-5-32-573 (Event Log Readers). SIDs keep rules
#            independent of the Windows display language, where group names are translated.
#   Member   SID of the account.
#   Ensure   Present (the default) or Absent.
# Only direct membership counts: membership through a nested or domain group is not checked.
# Reading works without elevation; changing membership needs an elevated session. A new
# membership is part of the account's token only after it signs in again.

function Get-ThemisLocalGroupMemberSid {
    <#
    .SYNOPSIS
        The SIDs of the direct members of a local group, or $null when the group does not exist.
        Separate so the tests can mock it.
    #>
    [CmdletBinding()]
    [OutputType([string[]], [object[]])]
    param([Parameter(Mandatory = $true)][string]$Group)

    $name = Resolve-ThemisLocalGroupName -Group $Group
    if (-not $name) { return $null }
    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME/$name,group"
    $members = [System.Collections.Generic.List[string]]::new()
    foreach ($member in @($adsi.psbase.Invoke('Members'))) {
        $bytes = $member.GetType().InvokeMember('objectSid', 'GetProperty', $null, $member, $null)
        if ($bytes) { $members.Add((New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value) }
    }
    # The comma keeps an empty group as an empty list instead of $null (which means "no such group").
    return , $members.ToArray()
}

function Resolve-ThemisLocalGroupName {
    <#
    .SYNOPSIS
        The local name of a group SID (for example "Event Log Readers"), or $null if it does not exist.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Group)

    try {
        $account = (New-Object System.Security.Principal.SecurityIdentifier($Group)).Translate([System.Security.Principal.NTAccount]).Value
        return ($account -split '\\')[-1]
    }
    catch { return $null }
}

function Set-ThemisLocalGroupMember {
    <#
    .SYNOPSIS
        Adds an account to a local group or removes it, both by SID.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$Group,
        [Parameter(Mandatory = $true)][string]$Member,
        [Parameter(Mandatory = $true)][ValidateSet('Present', 'Absent')][string]$Ensure
    )

    $name = Resolve-ThemisLocalGroupName -Group $Group
    if (-not $name) { throw "The local group $Group does not exist." }
    if (-not $PSCmdlet.ShouldProcess("$name ($Group)", "$(if ($Ensure -eq 'Present') { 'Add' } else { 'Remove' }) member $Member")) { return }
    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME/$name,group"
    # The ADSI adapter returns the COM result ($null) to the pipeline: discard it, or it ends up in the rule result.
    if ($Ensure -eq 'Present') { $null = $adsi.Add("WinNT://$Member") }
    else { $null = $adsi.Remove("WinNT://$Member") }
}

function Invoke-ThemisLocalGroupMemberRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $result = [ordered]@{ Status = 'Unknown'; IsCompliant = $false; Reason = ''; Actual = $null }

    $sidPattern = '^S-1-\d+(-\d+)+$'
    $group = "$($Rule.Group)"
    $member = "$($Rule.Member)"
    $ensure = if ($Rule.Ensure) { "$($Rule.Ensure)" } else { 'Present' }
    if ($group -notmatch $sidPattern) {
        $result.Status = 'Error'
        $result.Reason = "Group must be the SID of a local group, such as S-1-5-32-573: '$group'."
        return $result
    }
    if ($member -notmatch $sidPattern) {
        $result.Status = 'Error'
        $result.Reason = "Member must be the SID of an account: '$member'."
        return $result
    }
    if ($ensure -notin 'Present', 'Absent') {
        $result.Status = 'Error'
        $result.Reason = "Ensure must be Present or Absent: '$ensure'."
        return $result
    }

    try {
        $members = Get-ThemisLocalGroupMemberSid -Group $group
        if ($null -eq $members) {
            $result.Status = 'NotApplicable'
            $result.IsCompliant = $true
            $result.Reason = "This Windows has no local group $group."
            $result.Data = @{ Missing = $true }
            return $result
        }
        $isMember = @($members) -contains $member
        $result.Actual = $isMember
        $result.Data = @{ Missing = $false; Value = $isMember; Members = @($members) }
        if ($isMember -eq ($ensure -eq 'Present')) {
            $result.Status = 'Compliant'
            $result.IsCompliant = $true
            $result.Reason = "$member is $(if ($isMember) { 'a member' } else { 'not a member' }) of $group."
            return $result
        }

        $result.Status = 'Non-Compliant'
        $result.Reason = "$member is $(if ($isMember) { 'a member' } else { 'not a member' }) of $group; required: $ensure."
        if ($Mode -ne 'Enforce') { return $result }
        if (-not (Test-ThemisElevated)) {
            $result.Status = 'NeedsElevation'
            $result.Reason = 'Changing the members of a local group requires an elevated session (Run as administrator).'
            return $result
        }

        $null = Set-ThemisLocalGroupMember -Group $group -Member $member -Ensure $ensure -Confirm:$false
        $now = Get-ThemisLocalGroupMemberSid -Group $group
        $after = @($now) -contains $member
        $result.Actual = $after
        $result.Data = @{ Missing = $false; Value = $after }
        if ($after -eq ($ensure -eq 'Present')) {
            # Undoing the change is the opposite membership.
            $result.Previous = [ordered]@{ Group = $group; Member = $member; Ensure = $(if ($isMember) { 'Present' } else { 'Absent' }) }
            $result.Status = 'Fixed'
            $result.IsCompliant = $true
            $result.Reason = "$member $(if ($ensure -eq 'Present') { 'added to' } else { 'removed from' }) $group (it applies from the next sign-in)."
        }
        else {
            $result.Status = 'EnforceFailed'
            $result.Reason = "The membership of $member in $group did not change."
        }
    }
    catch {
        $result.Status = 'Error'
        $result.Reason = "Provider Error: $_"
    }
    return $result
}
