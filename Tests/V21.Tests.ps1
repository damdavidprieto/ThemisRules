# ThemisRules 2.1: structured antivirus data, console user, root certificates, driver names, the signature cache,
# reports in other languages, rule batches as an engine, and Test-ThemisPolicy -InputObject.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../ThemisRules.psd1') -Force
}

Describe 'Antivirus facts' {
    It 'lists every antivirus as an object and gives a documented Defender mode' {
        Mock -ModuleName ThemisRules Get-CimInstance {
            @([pscustomobject]@{ displayName = 'Windows Defender'; productState = 0x60100 }, [pscustomobject]@{ displayName = 'Other AV'; productState = 0x61100 })
        } -ParameterFilter { $Namespace -eq 'root/SecurityCenter2' }
        $f = InModuleScope ThemisRules { Read-ThemisAntivirusFact }
        @($f.AntivirusProducts).Count | Should -Be 2
        ($f.AntivirusProducts | Where-Object Name -EQ 'Other AV').Enabled | Should -BeTrue
        ($f.AntivirusProducts | Where-Object Name -EQ 'Windows Defender').Enabled | Should -BeFalse
        $f.DefenderMode | Should -Be 'Passive'
        $f.ThirdPartyAntivirus | Should -Be 'Other AV'
    }

    It 'maps every running mode of Get-MpComputerStatus to Active, Passive, Off, EDR Block or Unknown' {
        Mock -ModuleName ThemisRules Get-CimInstance { @() } -ParameterFilter { $Namespace -eq 'root/SecurityCenter2' }
        foreach ($case in @(@('Normal', 'Active'), @('Passive Mode', 'Passive'), @('SxS Passive Mode', 'Passive'), @('EDR Block Mode', 'EDR Block'), @('Not running', 'Off'), @('Something new', 'Unknown'))) {
            $script:mode = $case[0]
            Mock -ModuleName ThemisRules Get-MpComputerStatus { [pscustomobject]@{ AMRunningMode = $script:mode; AntivirusEnabled = $true } }
            (InModuleScope ThemisRules { Read-ThemisAntivirusFact }).DefenderMode | Should -Be $case[1] -Because $case[0]
        }
    }
}

Describe 'Console user, drivers and root certificates' {
    It 'tells whether the account at the screen is an administrator when it is not the one of the session' -Skip:(-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) {
        Mock -ModuleName ThemisRules Get-CimInstance { [pscustomobject]@{ UserName = 'NT AUTHORITY\SYSTEM' } } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }
        Mock -ModuleName ThemisRules Get-ThemisLocalGroupMemberSid { , @('S-1-5-18') }
        $f = InModuleScope ThemisRules { $script:ThemisRunCache = @{}; Read-ThemisConsoleFact }
        $f.ConsoleUser | Should -Be 'NT AUTHORITY\SYSTEM'
        $f.ConsoleUserSid | Should -Be 'S-1-5-18'
        $f.ConsoleUserIsAdministrator | Should -BeTrue
        Mock -ModuleName ThemisRules Get-ThemisLocalGroupMemberSid { , @('S-1-5-32-544') }
        (InModuleScope ThemisRules { Read-ThemisConsoleFact }).ConsoleUserIsAdministrator | Should -BeFalse
    }

    It 'names the drivers that give direct access to hardware' {
        Mock -ModuleName ThemisRules Get-CimInstance {
            @([pscustomobject]@{ Name = 'RTCore64'; DisplayName = 'MSI Afterburner driver'; PathName = '\??\C:\Tools\RTCore64.sys' }, [pscustomobject]@{ Name = 'tcpip'; DisplayName = 'TCP/IP'; PathName = 'C:\Windows\System32\drivers\tcpip.sys' })
        } -ParameterFilter { $ClassName -eq 'Win32_SystemDriver' }
        $f = InModuleScope ThemisRules { Read-ThemisDriversFact }
        $f.HwAccessDrivers | Should -Be 'RTCore64.sys (MSI Afterburner driver)'
        $f.HwAccessDriverList[0].Path | Should -Be 'C:\Tools\RTCore64.sys'
        $f.NoHwAccessDrivers | Should -BeFalse
    }

    It 'recognizes antivirus roots, and never removes one' {
        InModuleScope ThemisRules {
            Test-ThemisAntivirusRoot 'CN=Bitdefender Personal CA.Net-Defender, OU=IDS, O=Bitdefender' | Should -BeTrue
            Test-ThemisAntivirusRoot 'CN=Fiddler Root' | Should -BeFalse
        }
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        Mock -ModuleName ThemisRules Get-ThemisRootCertificate { [pscustomobject]@{ Subject = 'CN=Bitdefender Personal CA.Net-Defender, O=Bitdefender'; RawData = 'AA==' } }
        Mock -ModuleName ThemisRules Set-ThemisRootCertificate { }
        $r = Invoke-ThemisRule -Type RootCertificate -Rule @{ ID = 'RC'; Name = 'x'; Thumbprint = ('A' * 40); Store = 'LocalMachine'; Ensure = 'Absent' } -Mode Enforce
        $r.Status | Should -Be 'Manual'
        $r.Reason | Should -Match 'antivirus'
        Should -Invoke -ModuleName ThemisRules Set-ThemisRootCertificate -Times 0 -Exactly
    }
}

Describe 'Get-ThemisServiceProgram' {
    It 'returns the program of <Line>' -TestCases @(
        @{ Line = '"C:\Program Files\App\svc.exe" -run'; Expected = 'C:\Program Files\App\svc.exe' }
        @{ Line = 'C:\Program Files\App\svc.exe -run'; Expected = 'C:\Program Files\App\svc.exe' }
        @{ Line = 'C:\App\svc -k netsvcs'; Expected = 'C:\App\svc' }
    ) {
        Get-ThemisServiceProgram $Line | Should -Be $Expected
    }

    It 'takes service objects from the pipeline' {
        @([pscustomobject]@{ PathName = 'C:\A\a.exe /x' }, [pscustomobject]@{ PathName = '"C:\B\b.exe"' }) | Get-ThemisServiceProgram | Should -Be @('C:\A\a.exe', 'C:\B\b.exe')
    }
}

Describe 'Signature cache' {
    BeforeEach {
        InModuleScope ThemisRules { $script:ThemisSignatureCache = @{ 'c:\app\svc.exe|100|638000000000000000' = 'Valid'; 'c:\app\bad.exe|5|638000000000000001' = 'NotSigned' } }
        $script:file = Join-Path $TestDrive 'signatures.json'
    }

    It 'saves the checked signatures and reads them back in another session' {
        Mock -ModuleName ThemisRules Test-ThemisElevated { $false }
        (Export-ThemisSignatureCache -Path $script:file).FullName | Should -Be $script:file
        InModuleScope ThemisRules { $script:ThemisSignatureCache = @{} }
        Import-ThemisSignatureCache -Path $script:file | Should -Be 2
        (InModuleScope ThemisRules { $script:ThemisSignatureCache['c:\app\svc.exe|100|638000000000000000'] }) | Should -Be 'Valid'
        Import-ThemisSignatureCache -Path (Join-Path $TestDrive 'none.json') | Should -Be 0
    }

    It 'is refused in an elevated session when users without elevation could change it, and when it is not a cache' {
        $null = Export-ThemisSignatureCache -Path $script:file
        Mock -ModuleName ThemisRules Test-ThemisElevated { $true }
        Mock -ModuleName ThemisRules Test-ThemisTrustedPath { $false }
        { Import-ThemisSignatureCache -Path $script:file } | Should -Throw '*does not trust it*'
        Mock -ModuleName ThemisRules Test-ThemisElevated { $false }
        Set-Content -Path $script:file -Value '{"Entries":{}}'
        { Import-ThemisSignatureCache -Path $script:file } | Should -Throw '*not a signature cache*'
    }
}

Describe 'Reports in another language' {
    BeforeAll {
        $script:results = @(
            [pscustomobject]@{ Policy = 'P'; ID = 'A'; Type = 'Registry'; Name = 'Uno'; Severity = 'High'; Status = 'Non-Compliant'; IsCompliant = $false; Reason = 'mal'; Category = '<b>Red</b>' }
            [pscustomobject]@{ Policy = 'P'; ID = 'B'; Type = 'Service'; Name = 'Dos'; Severity = 'Low'; Status = 'Compliant'; IsCompliant = $true; Reason = 'bien'; Category = 'Sistema' }
        )
    }

    It 'uses the title, language, labels, value labels and columns given, and encodes all of them' {
        $file = $script:results | Export-ThemisReport -Path (Join-Path $TestDrive 'es.html') -Title 'Informe <de> seguridad' -Language es `
            -Columns ID, Category, Name, Status -Labels @{ Compliance = 'Cumplimiento'; Of = 'de'; Rules = 'reglas'; Category = 'Zona'; Status = 'Estado' } `
            -ValueLabels @{ Compliant = 'Cumple'; 'Non-Compliant' = 'No cumple'; High = 'Alta' }
        $html = Get-Content $file.FullName -Raw -Encoding UTF8
        $html | Should -Match '<html lang="es">'
        $html | Should -Match '<title>Informe &lt;de&gt; seguridad</title>'
        $html | Should -Match 'Cumplimiento: <strong>50%</strong> \(1 de 2 reglas\)'
        $html | Should -Match '<th>ID</th><th>Zona</th><th>Name</th><th>Estado</th>'
        $html | Should -Match '<td>&lt;b&gt;Red&lt;/b&gt;</td>'
        $html | Should -Match '<td>No cumple</td>'
        $html | Should -Match '1 Alta'
        $html | Should -Match 'td:nth-child\(4\)\{color'
        $html | Should -Not -Match '<b>Red'
    }

    It 'keeps the English report by default' {
        $html = Get-Content ($script:results | Export-ThemisReport -Path (Join-Path $TestDrive 'en.html')).FullName -Raw
        $html | Should -Match '<html lang="en"><head><meta charset="utf-8"><title>ThemisRules report</title>'
        $html | Should -Match '<th>ID</th><th>Type</th><th>Name</th><th>Level</th><th>Severity</th><th>Status</th><th>Reason</th>'
    }
}

Describe 'Rule batches as the engine of another tool' -Skip:(-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) {
    BeforeEach {
        New-Item -Path 'TestRegistry:\Engine' -Force | Out-Null
        New-ItemProperty -Path 'TestRegistry:\Engine' -Name 'A' -Value 1 -PropertyType DWord | Out-Null
        New-ItemProperty -Path 'TestRegistry:\Engine' -Name 'B' -Value 1 -PropertyType DWord | Out-Null
    }

    It 'gives each result as soon as its rule is done, with its own restore rules and the tag of its item' {
        $log = [System.Collections.Generic.List[string]]::new()
        $mine = @(@{ Id = 'MY-1'; Value = 'A' }, @{ Id = 'MY-2'; Value = 'B' })
        $results = & {
            foreach ($m in $mine) {
                $log.Add("in $($m.Id)")
                @{ Type = 'Registry'; Rule = @{ ID = $m.Id; Name = $m.Value; Path = 'TestRegistry:\Engine'; ValueName = $m.Value; Value = 2; Type = 'DWord' }; Tag = $m }
            }
        } | Invoke-ThemisRule -Mode Enforce | ForEach-Object { $log.Add("out $($_.Tag.Id)"); $_ }
        @($log) | Should -Be @('in MY-1', 'out MY-1', 'in MY-2', 'out MY-2')
        $results[1].Tag.Value | Should -Be 'B'
        # Undo only the first change.
        $null = Invoke-ThemisRule -Type Registry -Rule $results[0].Previous[0] -Mode Enforce
        (Get-ItemProperty 'TestRegistry:\Engine').A | Should -Be 1
        (Get-ItemProperty 'TestRegistry:\Engine').B | Should -Be 2
    }
}

Describe 'Test-ThemisPolicy -InputObject' {
    It 'checks a policy in memory as it would check the same file' {
        $policy = @{ Meta = @{ Name = 'Mine'; Version = '1.0.0' }; ServiceRules = @(@{ ID = 'S1'; Name = 'Spooler'; StartupTyp = 'Disabled' }) }
        $fromObject = @(Test-ThemisPolicy -InputObject $policy)
        $file = Join-Path $TestDrive 'mine.json'
        $policy | ConvertTo-Json -Depth 6 | Set-Content -Path $file
        $fromFile = @(Test-ThemisPolicy -Path $file)
        $fromObject.Count | Should -Be 1
        $fromObject[0].Problem | Should -Be $fromFile[0].Problem
        $fromObject[0].Problem | Should -Match 'did you mean StartupType'
    }
}
