BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../ThemisRules.psd1') -Force
}

Describe 'ScheduledTask provider' {
    BeforeEach {
        $script:task = [pscustomobject]@{ State = 'Ready'; Xml = '<Task>definition</Task>' }
        Mock -ModuleName ThemisRules Get-ThemisScheduledTaskState { $script:task }
        Mock -ModuleName ThemisRules Set-ThemisScheduledTaskState {
            switch ($Ensure) {
                'Disabled' { $script:task.State = 'Disabled' }
                'Enabled' { $script:task.State = 'Ready' }
                'Absent' { $script:task = $null }
                'Present' { $script:task = [pscustomobject]@{ State = 'Ready'; Xml = $Xml } }
            }
        }
        $script:rule = @{ ID = 'T1'; Name = 'updater'; TaskPath = '\Vendor\'; TaskName = 'Updater' }
    }

    It 'disables a task and restores it as enabled' {
        $r = Invoke-ThemisRule -Type ScheduledTask -Rule $script:rule -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        $script:task.State | Should -Be 'Disabled'
        $r.Previous[0].Ensure | Should -Be 'Enabled'
        $null = Invoke-ThemisRule -Type ScheduledTask -Rule $r.Previous[0] -Mode Enforce
        $script:task.State | Should -Be 'Ready'
    }

    It 'removes a task and restores it from its definition' {
        $rule = $script:rule.Clone(); $rule.Ensure = 'Absent'
        $r = Invoke-ThemisRule -Type ScheduledTask -Rule $rule -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        $script:task | Should -BeNullOrEmpty
        $r.Previous[0].Ensure | Should -Be 'Present'
        $r.Previous[0].Xml | Should -Be '<Task>definition</Task>'
        $null = Invoke-ThemisRule -Type ScheduledTask -Rule $r.Previous[0] -Mode Enforce
        $script:task.Xml | Should -Be '<Task>definition</Task>'
    }

    It 'treats a missing task as disabled, refuses bad names and asks for elevation when denied' {
        $script:task = $null
        (Invoke-ThemisRule -Type ScheduledTask -Rule $script:rule).Status | Should -Be 'Compliant'
        $bad = $script:rule.Clone(); $bad.TaskPath = 'Vendor'
        (Invoke-ThemisRule -Type ScheduledTask -Rule $bad).Status | Should -Be 'Error'
        $script:task = [pscustomobject]@{ State = 'Ready'; Xml = '' }
        Mock -ModuleName ThemisRules Set-ThemisScheduledTaskState { throw [System.UnauthorizedAccessException]::new('denied') }
        (Invoke-ThemisRule -Type ScheduledTask -Rule $script:rule -Mode Enforce).Status | Should -Be 'NeedsElevation'
    }
}

Describe 'FirewallRule provider' {
    BeforeEach {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        $script:fw = $null
        Mock -ModuleName ThemisRules Get-ThemisFirewallRule { $script:fw }
        Mock -ModuleName ThemisRules Set-ThemisFirewallRule {
            $script:fw = if ($Ensure -eq 'Present') { [pscustomobject]@{ Direction = $Direction; Action = $Action; Program = $Program; Enabled = $true } } else { $null }
        }
        $script:rule = @{ ID = 'W1'; Name = 'mshta'; DisplayName = 'Block mshta'; Program = '%SystemRoot%\System32\mshta.exe' }
    }

    It 'creates the block rule and restores by removing it' {
        $r = Invoke-ThemisRule -Type FirewallRule -Rule $script:rule -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        $script:fw.Action | Should -Be 'Block'
        $script:fw.Direction | Should -Be 'Outbound'
        $r.Previous[0].Ensure | Should -Be 'Absent'
        $null = Invoke-ThemisRule -Type FirewallRule -Rule $r.Previous[0] -Mode Enforce
        $script:fw | Should -BeNullOrEmpty
    }

    It 'is compliant when the rule is there, refuses a program that is not an .exe path, and needs elevation' {
        $script:fw = [pscustomobject]@{ Direction = 'Outbound'; Action = 'Block'; Program = 'C:\Windows\System32\mshta.exe'; Enabled = $true }
        Mock -ModuleName ThemisRules Get-ThemisFirewallRule { $script:fw }
        $env:SystemRoot | Should -Not -BeNullOrEmpty
        if ($env:SystemRoot -eq 'C:\Windows') { (Invoke-ThemisRule -Type FirewallRule -Rule $script:rule).Status | Should -Be 'Compliant' }
        $bad = $script:rule.Clone(); $bad.Program = 'mshta'
        (Invoke-ThemisRule -Type FirewallRule -Rule $bad).Status | Should -Be 'Error'
        $script:fw = $null
        Mock -ModuleName ThemisRules Test-ThemisElevated { $false }
        (Invoke-ThemisRule -Type FirewallRule -Rule $script:rule -Mode Enforce).Status | Should -Be 'NeedsElevation'
    }
}

Describe 'RootCertificate provider' {
    BeforeAll {
        # A throwaway self-signed certificate, made only to have real certificate bytes; it is never installed.
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Themis Test Root', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $cert = $req.CreateSelfSigned([datetimeoffset]::Now, [datetimeoffset]::Now.AddDays(1))
        $script:raw = [Convert]::ToBase64String($cert.RawData)
        $script:thumb = $cert.Thumbprint
    }
    BeforeEach {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        $script:cert = [pscustomobject]@{ Subject = 'CN=Themis Test Root'; RawData = $script:raw }
        Mock -ModuleName ThemisRules Get-ThemisRootCertificate { $script:cert }
        Mock -ModuleName ThemisRules Set-ThemisRootCertificate {
            $script:cert = if ($Ensure -eq 'Absent') { $null } else { [pscustomobject]@{ Subject = 'CN=Themis Test Root'; RawData = $RawData } }
        }
    }

    It 'removes a root certificate and restores the same certificate' {
        $r = Invoke-ThemisRule -Type RootCertificate -Rule @{ ID = 'C1'; Name = 'test'; Thumbprint = $script:thumb } -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        $script:cert | Should -BeNullOrEmpty
        $r.Previous[0].RawData | Should -Be $script:raw
        $null = Invoke-ThemisRule -Type RootCertificate -Rule $r.Previous[0] -Mode Enforce
        $script:cert.RawData | Should -Be $script:raw
    }

    It 'refuses to add a certificate whose bytes do not match the thumbprint' {
        $r = Invoke-ThemisRule -Type RootCertificate -Rule @{ ID = 'C2'; Name = 'test'; Thumbprint = ('A' * 40); Ensure = 'Present'; RawData = $script:raw } -Mode Enforce
        $r.Status | Should -Be 'Error'
        $r.Reason | Should -Match 'not AAAA'
    }
}

Describe 'FileSignature provider' {
    It 'is compliant with a valid signature from the publisher, Manual otherwise, and never changes anything' {
        Mock -ModuleName ThemisRules Get-ThemisFileSignature { [pscustomobject]@{ Status = 'Valid'; Signer = 'CN=Microsoft Corporation, O=Microsoft Corporation' } }
        $rule = @{ ID = 'S1'; Name = 'pwsh'; Path = 'C:\x\pwsh.exe'; Publisher = 'O=Microsoft Corporation' }
        (Invoke-ThemisRule -Type FileSignature -Rule $rule).Status | Should -Be 'Compliant'
        $other = $rule.Clone(); $other.Publisher = 'O=Someone Else'
        (Invoke-ThemisRule -Type FileSignature -Rule $other -Mode Enforce).Status | Should -Be 'Manual'
        Mock -ModuleName ThemisRules Get-ThemisFileSignature { [pscustomobject]@{ Status = 'NotSigned'; Signer = '' } }
        (Invoke-ThemisRule -Type FileSignature -Rule $rule).Reason | Should -Match 'no valid signature'
        Mock -ModuleName ThemisRules Get-ThemisFileSignature { $null }
        $missing = $rule.Clone(); $missing.AllowMissing = $true
        (Invoke-ThemisRule -Type FileSignature -Rule $missing).Status | Should -Be 'NotApplicable'
    }
}

Describe 'AppLocker provider' {
    BeforeEach {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        Mock -ModuleName ThemisRules Get-ThemisAppIdServiceStatus { 'Running' }
        $script:policy = '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="NotConfigured"><FilePathRule Id="11111111-1111-1111-1111-111111111111" Name="Mine" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="D:\Tools\*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>'
        Mock -ModuleName ThemisRules Get-ThemisAppLockerPolicyXml { $script:policy }
        Mock -ModuleName ThemisRules Set-ThemisAppLockerPolicyXml { $script:policy = $Xml }
        $script:rule = @{ ID = 'A1'; Name = 'exe'; Collection = 'Exe'; Mode = 'AuditOnly'; AllowPaths = @('%PROGRAMDATA%\Tool\*') }
    }

    It 'sets audit mode with the standard rules, keeps rules that are not its own, and is then compliant' {
        $r = Invoke-ThemisRule -Type AppLocker -Rule $script:rule -Mode Enforce
        $r.Status | Should -Be 'Fixed'
        $doc = [xml]$script:policy
        $col = $doc.AppLockerPolicy.RuleCollection
        $col.GetAttribute('EnforcementMode') | Should -Be 'AuditOnly'
        $names = @($col.ChildNodes | ForEach-Object { $_.GetAttribute('Name') })
        $names | Should -Contain 'Mine'
        $names | Should -Contain 'Themis: Windows folder'
        $names | Should -Contain 'Themis: Path %PROGRAMDATA%\Tool\*'
        (Invoke-ThemisRule -Type AppLocker -Rule $script:rule).Status | Should -Be 'Compliant'
    }

    It 'restores the exact collection it replaced' {
        $before = ([xml]$script:policy).AppLockerPolicy.RuleCollection.OuterXml
        $r = Invoke-ThemisRule -Type AppLocker -Rule $script:rule -Mode Enforce
        $r.Previous[0].RestoreXml | Should -Be $before
        $back = Invoke-ThemisRule -Type AppLocker -Rule $r.Previous[0] -Mode Enforce
        $back.Status | Should -Be 'Fixed'
        ([xml]$script:policy).AppLockerPolicy.RuleCollection.OuterXml | Should -Be $before
    }

    It 'replaces its own old rules instead of piling them up' {
        $null = Invoke-ThemisRule -Type AppLocker -Rule $script:rule -Mode Enforce
        $changed = $script:rule.Clone(); $changed.AllowPaths = @('%PROGRAMDATA%\Other\*')
        (Invoke-ThemisRule -Type AppLocker -Rule $changed).Status | Should -Be 'Non-Compliant'
        $null = Invoke-ThemisRule -Type AppLocker -Rule $changed -Mode Enforce
        $names = @(([xml]$script:policy).AppLockerPolicy.RuleCollection.ChildNodes | ForEach-Object { $_.GetAttribute('Name') })
        $names | Should -Not -Contain 'Themis: Path %PROGRAMDATA%\Tool\*'
        $names | Should -Contain 'Themis: Path %PROGRAMDATA%\Other\*'
    }

    It 'leaves the exceptions out of the allowed paths, and a change in them is a new rule' {
        $broad = $script:rule.Clone()
        $broad.AllowPaths = @('%OSDRIVE%\Users\*')
        $broad.AllowPathExceptions = @('%OSDRIVE%\Users\*\Downloads\*', '%OSDRIVE%\Users\*\AppData\Local\Temp\*')
        $null = Invoke-ThemisRule -Type AppLocker -Rule $broad -Mode Enforce
        $col = ([xml]$script:policy).AppLockerPolicy.RuleCollection
        $users = @($col.ChildNodes | Where-Object { $_.GetAttribute('Name') -eq 'Themis: Path %OSDRIVE%\Users\*' })[0]
        @($users.Exceptions.FilePathCondition | ForEach-Object { $_.GetAttribute('Path') }) | Should -Be @('%OSDRIVE%\Users\*\Downloads\*', '%OSDRIVE%\Users\*\AppData\Local\Temp\*')
        (Invoke-ThemisRule -Type AppLocker -Rule $broad).Status | Should -Be 'Compliant'
        $fewer = $broad.Clone(); $fewer.AllowPathExceptions = @('%OSDRIVE%\Users\*\Downloads\*')
        (Invoke-ThemisRule -Type AppLocker -Rule $fewer).Status | Should -Be 'Non-Compliant'
        # The standard rules never get exceptions.
        $windows = @($col.ChildNodes | Where-Object { $_.GetAttribute('Name') -eq 'Themis: Windows folder' })[0]
        $windows.Exceptions | Should -BeNullOrEmpty
    }

    It 'says when the Application Identity service is not running, and refuses bad collections' {
        Mock -ModuleName ThemisRules Get-ThemisAppIdServiceStatus { 'Stopped' }
        (Invoke-ThemisRule -Type AppLocker -Rule $script:rule).Reason | Should -Match 'AppIDSvc'
        $bad = $script:rule.Clone(); $bad.Collection = 'Everything'
        (Invoke-ThemisRule -Type AppLocker -Rule $bad).Status | Should -Be 'Error'
    }
}
