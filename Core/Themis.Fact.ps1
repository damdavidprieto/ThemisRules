# ThemisRules: facts about this machine, for AppliesIf conditions and Check rules.
#
# A fact is a value that describes the machine (OSBuild, SecureBootOn, BitLockerSystemDrive...). The caller can
# pass facts with -Facts; any built-in fact that a rule uses and the caller did not give is read here, once per
# run, and only the sources that are needed are read. Every reader only reads: nothing here changes the machine.
# A fact that cannot be read (no permission, not supported) is $null, which a Check rule reports as Unknown.
#
# Facts come from sources: one reader per source, so related facts share one query. The readers are separate
# functions so the tests can replace them.

$script:ThemisFactCatalog = [ordered]@{
    OSBuild                 = @{ Source = 'OS'; Description = 'Windows build number, such as 26100.' }
    OSName                  = @{ Source = 'OS'; Description = 'Windows edition, such as Windows 11 Pro.' }
    DisplayVersion          = @{ Source = 'OS'; Description = 'Windows version, such as 24H2.' }
    IsElevated              = @{ Source = 'OS'; Description = 'The session runs as administrator.' }
    UserIsAdministrator     = @{ Source = 'OS'; Description = 'The account of the session is a member of Administrators, elevated or not.' }
    DomainJoined            = @{ Source = 'OS'; Description = 'The machine is joined to a domain.' }
    ConsoleUser             = @{ Source = 'Console'; Description = 'The account signed in at the screen (not always the one running an elevated session).' }
    ConsoleUserSid          = @{ Source = 'Console'; Description = 'SID of that account.' }
    ConsoleUserIsAdministrator = @{ Source = 'Console'; Description = 'That account is a member of Administrators (direct membership when it is not the account of this session).' }
    IsLaptop                = @{ Source = 'OS'; Description = 'The machine has a battery.' }
    UefiFirmware            = @{ Source = 'Firmware'; Description = 'The machine started with UEFI firmware (not legacy BIOS).' }
    SecureBootOn            = @{ Source = 'Firmware'; Description = 'Secure Boot is on.' }
    SecureBootCertsUpdated  = @{ Source = 'Firmware'; Description = 'Secure Boot uses the 2023 certificates (UEFICA2023Status is Updated).' }
    TpmPresent              = @{ Source = 'Firmware'; Description = 'The machine has a TPM.' }
    VbsCapable              = @{ Source = 'DeviceGuard'; Description = 'The hardware supports virtualization-based security.' }
    VbsRunning              = @{ Source = 'DeviceGuard'; Description = 'Virtualization-based security is running.' }
    HvciRunning             = @{ Source = 'DeviceGuard'; Description = 'Memory integrity (hypervisor-protected code integrity) is running.' }
    CredentialGuardRunning  = @{ Source = 'DeviceGuard'; Description = 'Credential Guard is running.' }
    KernelDmaProtection     = @{ Source = 'DeviceGuard'; Description = 'Kernel DMA protection is on (Thunderbolt and USB4 devices cannot read memory freely).' }
    HasDmaPorts             = @{ Source = 'DeviceGuard'; Description = 'The machine has Thunderbolt or USB4 ports.' }
    BitLockerSystemDrive    = @{ Source = 'BitLocker'; Description = 'The system drive is protected by BitLocker.' }
    BitLockerStartupPin     = @{ Source = 'BitLocker'; Description = 'BitLocker asks for a PIN or a startup key at boot (needs elevation).' }
    AntivirusHealthy        = @{ Source = 'Antivirus'; Description = 'An antivirus registered in Windows Security is on and up to date.' }
    AntivirusStatus         = @{ Source = 'Antivirus'; Description = 'State of every registered antivirus, as text.' }
    AntivirusProducts       = @{ Source = 'Antivirus'; Description = 'Every registered antivirus, as objects with Name, Enabled and UpToDate.' }
    ThirdPartyAntivirus     = @{ Source = 'Antivirus'; Description = 'Registered antivirus products other than Microsoft Defender.' }
    DefenderActive          = @{ Source = 'Antivirus'; Description = 'Microsoft Defender Antivirus is the active antivirus.' }
    DefenderMode            = @{ Source = 'Antivirus'; Description = 'Active, Passive, Off, EDR Block or Unknown ($null when it cannot be read).' }
    LastSecurityUpdateDays  = @{ Source = 'Updates'; Description = 'Days since the newest installed security update.' }
    UpdatesRecent           = @{ Source = 'Updates'; Description = 'A security update was installed in the last 40 days.' }
    SmartAppControlState    = @{ Source = 'SmartAppControl'; Description = 'On, Evaluation or Off.' }
    SmartAppControlOn       = @{ Source = 'SmartAppControl'; Description = 'Smart App Control is on.' }
    AllAccountsHavePassword = @{ Source = 'Accounts'; Description = 'Every enabled local account requires a password.' }
    AccountsWithoutPassword = @{ Source = 'Accounts'; Description = 'Enabled local accounts that do not require a password.' }
    DnsServers              = @{ Source = 'Dns'; Description = 'Configured IPv4 DNS servers.' }
    DnsEncrypted            = @{ Source = 'Dns'; Description = 'Every configured DNS server has a DNS over HTTPS template.' }
    HasPrinters             = @{ Source = 'Devices'; Description = 'A physical or network printer is installed (not PDF, XPS or OneNote).' }
    HasBluetooth            = @{ Source = 'Devices'; Description = 'A Bluetooth adapter is present.' }
    HasCamera               = @{ Source = 'Devices'; Description = 'A camera is present.' }
    HasMicrophone           = @{ Source = 'Devices'; Description = 'A microphone is present.' }
    HasWifi                 = @{ Source = 'Devices'; Description = 'A Wi-Fi adapter is present.' }
    HasSmbShares            = @{ Source = 'Devices'; Description = 'The machine shares folders (other than the administrative shares).' }
    HwAccessDrivers         = @{ Source = 'Drivers'; Description = 'Loaded drivers known to give direct access to hardware (memory, ports, CPU registers).' }
    HwAccessDriverList      = @{ Source = 'Drivers'; Description = 'Those drivers, as objects with File, Name, DisplayName and Path.' }
    NoHwAccessDrivers       = @{ Source = 'Drivers'; Description = 'None of those drivers is loaded.' }
    UnsignedSystemServices  = @{ Source = 'Services'; Description = 'Services that run as SYSTEM a program outside Windows without a valid signature.' }
    SystemServicesSigned    = @{ Source = 'Services'; Description = 'Every service that runs as SYSTEM runs a signed program.' }
    AddedRootCertificates   = @{ Source = 'RootCertificates'; Description = 'Root certificates added by a person or a program, outside those of Windows, as objects with Store, Thumbprint, Name, Subject, NotAfter and Antivirus.' }
    NoAddedRootCerts        = @{ Source = 'RootCertificates'; Description = 'No root certificate was added, apart from those of an antivirus.' }
}

# Drivers of tuning and monitoring tools that read and write physical memory, ports or CPU registers from the kernel.
# They are signed, which is why malware loads them to switch off security software.
$script:ThemisHwAccessDriverPattern = '^(gdrv\d*|amdryzenmasterdriver|winring0(x64|_\d+_\d+_\d+)?|rtcore(32|64)|asio\d?|asrdrv\d+|glckio\d*|eneio64|eneio|inpoutx?64|inpout32|cpuz\d+_x64|hwrwdrv|ntiolib(_x64)?|msio(32|64)|atillk64|iqvw64e|dbutil_\d+_\d+|piddrv64|phymemx?64)\.sys$'

function Invoke-ThemisSafe {
    <#
    .SYNOPSIS
        Runs a reader and returns its value, or -Default when it fails or returns nothing.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][scriptblock]$Block, $Default = $null)
    try { $value = & $Block; if ($null -eq $value) { return $Default } return $value }
    catch { return $Default }
}

function Read-ThemisOSFact {
    <#
    .SYNOPSIS
        Facts about Windows, the session and the computer.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $cv = Invoke-ThemisSafe { Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop }
    $build = Invoke-ThemisSafe { [int]$cv.CurrentBuild }
    $name = Invoke-ThemisSafe { "$($cv.ProductName)" }
    # ProductName still says Windows 10 on Windows 11.
    if ($name -and $build -ge 22000) { $name = $name -replace 'Windows 10', 'Windows 11' }
    $cs = Invoke-ThemisSafe { Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop }
    # By SID, so it does not depend on the language; deny-only groups count: the account is still an administrator.
    $admin = Invoke-ThemisSafe {
        $rows = & (Get-ThemisSystemTool 'whoami.exe') /groups /fo csv /nh | ConvertFrom-Csv -Header 'Name', 'Type', 'Sid', 'Attributes'
        [bool]@($rows | Where-Object Sid -EQ 'S-1-5-32-544').Count
    }
    return @{
        OSBuild             = $build
        OSName              = $name
        DisplayVersion      = Invoke-ThemisSafe { "$($cv.DisplayVersion)" }
        IsElevated          = Test-ThemisElevated
        UserIsAdministrator = $admin
        DomainJoined        = Invoke-ThemisSafe { [bool]$cs.PartOfDomain }
        IsLaptop            = Invoke-ThemisSafe { [bool]@(Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop).Count }
    }
}

function Read-ThemisFirmwareFact {
    <#
    .SYNOPSIS
        Facts about the firmware, Secure Boot and the TPM.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $secureBoot = Invoke-ThemisSafe { [bool](Confirm-SecureBootUEFI -ErrorAction Stop) }
    if ($null -eq $secureBoot) {
        # Without elevation Confirm-SecureBootUEFI fails: the registry has the same state.
        $secureBoot = Invoke-ThemisSafe { [bool](Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name 'UEFISecureBootEnabled' -ErrorAction Stop) }
    }
    $certs = Invoke-ThemisSafe { "$(Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name 'UEFICA2023Status' -ErrorAction Stop)" }
    # Without elevation Get-Tpm can answer that there is no TPM instead of failing: it is only asked as administrator.
    $tpm = $null
    if (Test-ThemisElevated) { $tpm = Invoke-ThemisSafe { [bool](Get-Tpm -ErrorAction Stop).TpmPresent } }
    if ($null -eq $tpm) {
        # The TPM driver is found by service or ACPI ID, which do not depend on the language.
        $tpm = Invoke-ThemisSafe { [bool]@(Get-CimInstance -ClassName Win32_PnPEntity -Filter "Service='TPM' OR PNPDeviceID LIKE '%MSFT0101%' OR PNPDeviceID LIKE '%PNP0C31%'" -ErrorAction Stop).Count }
    }
    $uefi = $null
    if ($env:firmware_type) { $uefi = $env:firmware_type -eq 'UEFI' }
    return @{
        UefiFirmware           = $uefi
        SecureBootOn           = $secureBoot
        SecureBootCertsUpdated = $(if ($certs) { $certs -eq 'Updated' } else { $null })
        TpmPresent             = $tpm
    }
}

function Read-ThemisDeviceGuardFact {
    <#
    .SYNOPSIS
        Facts about virtualization-based security, memory integrity, Credential Guard and DMA protection.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $dg = Invoke-ThemisSafe { Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop }
    $running = @(Invoke-ThemisSafe { @($dg.SecurityServicesRunning) } @())
    # SystemDmaGuardPolicyInformation (202): the same query System Information uses.
    $dma = Invoke-ThemisSafe {
        if (-not ('ThemisRules.DmaGuard' -as [type])) {
            Add-Type -Namespace ThemisRules -Name DmaGuard -MemberDefinition '[DllImport("ntdll.dll")] public static extern int NtQuerySystemInformation(int infoClass, byte[] buffer, int length, out int returned);'
        }
        $buffer = New-Object byte[] 1
        $returned = 0
        if (('ThemisRules.DmaGuard' -as [type])::NtQuerySystemInformation(202, $buffer, 1, [ref]$returned) -ne 0) { return $null }
        [bool]$buffer[0]
    }
    return @{
        VbsCapable             = $(if ($dg) { @($dg.AvailableSecurityProperties) -contains 1 } else { $null })
        VbsRunning             = $(if ($dg) { [int]$dg.VirtualizationBasedSecurityStatus -eq 2 } else { $null })
        HvciRunning            = $(if ($dg) { $running -contains 2 } else { $null })
        CredentialGuardRunning = $(if ($dg) { $running -contains 1 } else { $null })
        KernelDmaProtection    = $dma
        HasDmaPorts            = Invoke-ThemisSafe { [bool]@(Get-CimInstance -ClassName Win32_PnPEntity -Filter "Name LIKE '%Thunderbolt%' OR Name LIKE '%USB4%'" -ErrorAction Stop).Count }
    }
}

function Read-ThemisBitLockerFact {
    <#
    .SYNOPSIS
        Facts about BitLocker on the system drive.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', '', Justification = 'Get-BitLockerVolume is only called when it exists; a missing module leaves the fact $null.')]
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    # The shell property is instant and works without elevation; Get-BitLockerVolume takes seconds and needs it.
    $state = Invoke-ThemisSafe {
        $shell = New-Object -ComObject Shell.Application
        $value = $shell.NameSpace(17).ParseName($env:SystemDrive).ExtendedProperty('System.Volume.BitLockerProtection')
        if ($null -eq $value) { return $null }
        # 1 on, 3 encrypting, 6 on and locked; 2 off, 5 suspended.
        @(1, 3, 6) -contains [int]$value
    }
    $volume = $null
    if (Test-ThemisElevated) { $volume = Invoke-ThemisSafe { Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop } }
    if ($null -eq $state -and $volume) { $state = "$($volume.ProtectionStatus)" -eq 'On' }
    $pin = $null
    if ($volume -and "$($volume.ProtectionStatus)" -eq 'On') {
        $pin = [bool]@($volume.KeyProtector | Where-Object { "$($_.KeyProtectorType)" -in 'TpmPin', 'TpmPinStartupKey', 'TpmStartupKey' }).Count
    }
    return @{ BitLockerSystemDrive = $state; BitLockerStartupPin = $pin }
}

function ConvertFrom-ThemisAntivirusState {
    <#
    .SYNOPSIS
        Decodes productState of a Windows Security antivirus: the second byte 0x10/0x11 means on, the third 0x00 up to date.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][long]$ProductState)
    $hex = '{0:X6}' -f $ProductState
    $hex = $hex.Substring($hex.Length - 6)
    $enabled = $hex.Substring(2, 2) -in '10', '11'
    $upToDate = $hex.Substring(4, 2) -eq '00'
    return [pscustomobject]@{
        Name = $Name; Enabled = $enabled; UpToDate = $upToDate
        Text = "${Name}: $(if ($enabled) { 'on' } else { 'off' }), $(if ($upToDate) { 'up to date' } else { 'out of date' })"
    }
}

function Read-ThemisAntivirusFact {
    <#
    .SYNOPSIS
        Facts about the antivirus products registered in Windows Security.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $products = @(Invoke-ThemisSafe { Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntivirusProduct -ErrorAction Stop } @())
    $states = @($products | Where-Object displayName | ForEach-Object { ConvertFrom-ThemisAntivirusState -Name "$($_.displayName)" -ProductState ([long]$_.productState) })
    $defender = @($states | Where-Object { $_.Name -match 'Windows Defender|Microsoft Defender' }) | Select-Object -First 1
    $facts = @{
        AntivirusHealthy    = $(if ($states.Count) { [bool]@($states | Where-Object { $_.Enabled -and $_.UpToDate }).Count } else { $null })
        AntivirusStatus     = (@($states | ForEach-Object Text) -join '; ')
        AntivirusProducts   = @($states | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Enabled = $_.Enabled; UpToDate = $_.UpToDate } })
        ThirdPartyAntivirus = (@($states | Where-Object { $_.Name -notmatch 'Windows Defender|Microsoft Defender' } | ForEach-Object Name | Select-Object -Unique) -join ', ')
        DefenderActive      = $null
        DefenderMode        = $null
    }
    if ($states.Count) {
        # With another antivirus as the main one, Defender is passive: Windows Security already says so, without the
        # seconds Get-MpComputerStatus takes.
        $facts.DefenderActive = [bool]($defender -and $defender.Enabled)
        $facts.DefenderMode = if (-not $defender) { 'Off' } elseif ($defender.Enabled) { 'Active' } else { 'Passive' }
    }
    else {
        # Windows Server has no Windows Security list.
        $mp = Invoke-ThemisSafe { Get-MpComputerStatus -ErrorAction Stop }
        if ($mp) {
            $facts.DefenderActive = [bool]("$($mp.AMRunningMode)" -eq 'Normal' -and $mp.AntivirusEnabled)
            # Always one of the documented values, whatever text this version of Defender uses.
            $facts.DefenderMode = switch -Regex ("$($mp.AMRunningMode)") { '^Normal$' { 'Active' } 'EDR Block' { 'EDR Block' } 'Passive' { 'Passive' } '^Not running$|^$' { 'Off' } default { 'Unknown' } }
        }
    }
    return $facts
}

function Get-ThemisLastSecurityUpdate {
    <#
    .SYNOPSIS
        Date of the newest security update in a list of Win32_QuickFixEngineering entries, or $null.
    .DESCRIPTION
        The description is always in English. When no entry is marked as a security update (Windows removes the ones a
        newer update replaces), the newest update of any kind is used, rather than raising a false alarm.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param([object[]]$Fixes)
    $dated = @($Fixes | Where-Object { $_ -and $_.InstalledOn })
    $security = @($dated | Where-Object { "$($_.Description)" -match 'Security' })
    $from = if ($security.Count) { $security } else { $dated }
    $newest = $from | Sort-Object { [datetime]$_.InstalledOn } -Descending | Select-Object -First 1
    if ($newest) { return [datetime]$newest.InstalledOn }
    return $null
}

function Read-ThemisUpdatesFact {
    <#
    .SYNOPSIS
        Facts about installed security updates.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $last = Get-ThemisLastSecurityUpdate -Fixes @(Invoke-ThemisSafe { Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop } @())
    $days = if ($last) { [int]((Get-Date) - $last).TotalDays } else { $null }
    # There is at least one security update a month: more than 40 days means updates are stuck.
    return @{ LastSecurityUpdateDays = $days; UpdatesRecent = $(if ($null -ne $days) { $days -le 40 } else { $null }) }
}

function Read-ThemisSmartAppControlFact {
    <#
    .SYNOPSIS
        Facts about Smart App Control (Windows 11 22H2 and later).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $value = Invoke-ThemisSafe { [int](Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name 'VerifiedAndReputablePolicyState' -ErrorAction Stop) }
    $state = switch ($value) { 0 { 'Off' } 1 { 'On' } 2 { 'Evaluation' } default { $null } }
    return @{ SmartAppControlState = $state; SmartAppControlOn = $(if ($null -ne $value) { $value -eq 1 } else { $null }) }
}

function Read-ThemisAccountsFact {
    <#
    .SYNOPSIS
        Facts about local accounts. Win32_UserAccount works without elevation.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $users = @(Invoke-ThemisSafe { Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop } @())
    $without = @($users | Where-Object { -not $_.Disabled -and -not $_.PasswordRequired } | ForEach-Object Name)
    return @{
        AllAccountsHavePassword = $(if ($users.Count) { $without.Count -eq 0 } else { $null })
        AccountsWithoutPassword = $without -join ', '
    }
}

function Read-ThemisDnsFact {
    <#
    .SYNOPSIS
        Facts about the DNS servers and DNS over HTTPS.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $templates = @(Invoke-ThemisSafe { Get-DnsClientDohServerAddress -ErrorAction Stop | ForEach-Object ServerAddress } @())
    $servers = @(Invoke-ThemisSafe { Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object ServerAddresses } @() | Where-Object { $_ } | Select-Object -Unique)
    return @{
        DnsServers   = $servers -join ', '
        DnsEncrypted = $(if ($servers.Count) { -not @($servers | Where-Object { $templates -notcontains $_ }).Count } else { $null })
    }
}

function Read-ThemisDevicesFact {
    <#
    .SYNOPSIS
        Facts about printers, radios, cameras, microphones and shared folders.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $virtual = 'PDF|XPS|OneNote|Fax|Send To|Microsoft Print'
    # One CIM query for every device class: Get-PnpDevice is several times slower.
    $pnp = @(Invoke-ThemisSafe { Get-CimInstance -ClassName Win32_PnPEntity -Filter "PNPClass='Bluetooth' OR PNPClass='Camera' OR PNPClass='Image' OR PNPClass='AudioEndpoint'" -ErrorAction Stop } @() | Where-Object { $_.Status -eq 'OK' })
    return @{
        # From the registry: Win32_Printer fails while the Print Spooler is stopped.
        HasPrinters   = Invoke-ThemisSafe {
            $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers'
            # The key only exists once a printer has been installed.
            if (-not (Test-Path -LiteralPath $key)) { return $false }
            [bool]@(Get-ChildItem -LiteralPath $key -ErrorAction Stop | Where-Object { $_.PSChildName -notmatch $virtual }).Count
        }
        HasBluetooth  = [bool]@($pnp | Where-Object PNPClass -EQ 'Bluetooth').Count
        HasCamera     = [bool]@($pnp | Where-Object { $_.PNPClass -in 'Camera', 'Image' }).Count
        # Capture endpoints (microphones) have IDs SWD\MMDEVAPI\{0.0.1.*}.
        HasMicrophone = [bool]@($pnp | Where-Object { $_.PNPClass -eq 'AudioEndpoint' -and $_.DeviceID -like 'SWD\MMDEVAPI\{0.0.1.*' }).Count
        HasWifi       = Invoke-ThemisSafe { [bool]@(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.NdisPhysicalMedium -eq 9 -or $_.InterfaceDescription -match 'Wireless|Wi-?Fi|802\.11' }).Count }
        HasSmbShares  = Invoke-ThemisSafe { [bool]@(Get-CimInstance -ClassName Win32_Share -ErrorAction Stop | Where-Object { $_.Type -eq 0 -and $_.Name -notmatch '\$$' }).Count }
    }
}

function Test-ThemisHwAccessDriver {
    <#
    .SYNOPSIS
        True when a driver path names a driver known to give direct access to hardware.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyString()][string]$Path)
    if (-not $Path) { return $false }
    return [System.IO.Path]::GetFileName(($Path -replace '^\\\?\?\\', '')) -match $script:ThemisHwAccessDriverPattern
}

function Read-ThemisDriversFact {
    <#
    .SYNOPSIS
        Facts about loaded drivers.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $drivers = @(Invoke-ThemisSafe { Get-CimInstance -ClassName Win32_SystemDriver -Filter "State='Running'" -ErrorAction Stop } @())
    $found = @($drivers | Where-Object { Test-ThemisHwAccessDriver $_.PathName } | ForEach-Object {
            $path = $_.PathName -replace '^\\\?\?\\', ''
            [pscustomobject]@{ File = [System.IO.Path]::GetFileName($path); Name = "$($_.Name)"; DisplayName = "$($_.DisplayName)"; Path = $path }
        } | Sort-Object File -Unique)
    # "file (name shown by Windows)", as in the driver list of System Information.
    $text = @($found | ForEach-Object { if ($_.DisplayName -and $_.DisplayName -ne $_.Name) { "$($_.File) ($($_.DisplayName))" } else { $_.File } })
    return @{ HwAccessDrivers = $text -join ', '; HwAccessDriverList = $found; NoHwAccessDrivers = $(if ($drivers.Count) { $found.Count -eq 0 } else { $null }) }
}

# Signatures already checked, by path, size and modification time: checking them takes seconds. Export-ThemisSignatureCache
# and Import-ThemisSignatureCache keep them between sessions.
$script:ThemisSignatureCache = @{}

function Read-ThemisServicesFact {
    <#
    .SYNOPSIS
        Facts about the programs that services run as SYSTEM.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $services = @(Invoke-ThemisSafe { Get-CimInstance -ClassName Win32_Service -Filter "StartName='LocalSystem'" -ErrorAction Stop } @())
    $windows = "$env:SystemRoot\"
    $unsigned = @(foreach ($service in $services) {
            $exe = Get-ThemisServiceProgram $service.PathName
            if (-not $exe -or $exe.StartsWith($windows, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) { continue }
            $item = Get-Item -LiteralPath $exe -ErrorAction SilentlyContinue
            if (-not $item) { continue }
            $key = '{0}|{1}|{2}' -f $exe.ToLowerInvariant(), $item.Length, $item.LastWriteTimeUtc.Ticks
            if (-not $script:ThemisSignatureCache.ContainsKey($key)) {
                $script:ThemisSignatureCache[$key] = "$(Invoke-ThemisSafe { (Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction Stop).Status } 'Unknown')"
            }
            if ($script:ThemisSignatureCache[$key] -ne 'Valid') { "$($service.Name) ($exe)" }
        })
    return @{ UnsignedSystemServices = $unsigned -join ', '; SystemServicesSigned = $(if ($services.Count) { $unsigned.Count -eq 0 } else { $null }) }
}

function Read-ThemisConsoleFact {
    <#
    .SYNOPSIS
        Facts about the account signed in at the screen.
    .DESCRIPTION
        An elevated session can belong to another administrator account (Run as administrator with other
        credentials): rules about "your account" are about the one at the screen.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $user = Invoke-ThemisSafe { "$((Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName)" }
    $facts = @{ ConsoleUser = $user; ConsoleUserSid = $null; ConsoleUserIsAdministrator = $null }
    if (-not $user) { return $facts }
    $sid = Invoke-ThemisSafe { (New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).Value }
    $facts.ConsoleUserSid = $sid
    if (-not $sid) { return $facts }
    if ($sid -eq [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {
        # The account of this session: its token says it, nested groups included.
        $facts.ConsoleUserIsAdministrator = (Read-ThemisFactSource -Source 'OS').UserIsAdministrator
    }
    else {
        $members = Invoke-ThemisSafe { Get-ThemisLocalGroupMemberSid -Group 'S-1-5-32-544' }
        if ($null -ne $members) { $facts.ConsoleUserIsAdministrator = @($members) -contains $sid }
    }
    return $facts
}

# The few certificates Windows itself keeps in the Root store; public authorities come from Windows Update into AuthRoot.
# Anything else in Root was added by a person or a program.
$script:ThemisBuiltinRoots = @(
    '0119E81BE9A14CD8E22F40AC118C687ECBA3F4D8', '06F1AA330B927B753A40E68CDF22E34BCBEF3352', '18F7C1FCC3090203FD5BAA2F861A754976C8DD25',
    '245C97DF7514E7CF2DF8BE72AE957B9E04741E85', '31F9FC8BA3805986B721EA7295C65B3A44534274', '3B1EFD3A66EA28B16697394703A72CA340A05BD5',
    '7F88CD7223F3C813818C994614A89C99FA3B5247', '8F43288AD272F3103B6FB1428485EA3014C0BCFE', '92B46C76E13054E104F230517E6E504D43AB10B5',
    'A43489159A520F0D93D032CCAF37E7FE20A8B419', 'BE36A4562FB2EE05DBB3D32323ADF445084ED656', 'CDD4EEAE6000AC7F40C3802C171E30148030C072',
    'DF3C24F9BFD666761B268073FE06D1CC8D4F82A4', '73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74', 'F40042E2E5F7E8EF8189FED15519AECE42C3BFA2'
)
# Antivirus products add their own root to inspect encrypted web traffic. Themis reports it, and never removes it.
$script:ThemisAntivirusRootPattern = '(?i)Bitdefender|Kaspersky|ESET|Avast|AVG |Norton|Symantec Endpoint|McAfee|Sophos|Trend Micro|Avira|F-Secure|Malwarebytes|Panda|G DATA|Webroot|Emsisoft'
$script:ThemisHyperVCertOid = '1.3.6.1.4.1.311.62.1.1.1'

function Test-ThemisAntivirusRoot {
    <#
    .SYNOPSIS
        True when a certificate subject names an antivirus product.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyString()][string]$Subject)
    return [bool]($Subject -match $script:ThemisAntivirusRootPattern)
}

function Test-ThemisHyperVRootCertificate {
    <#
    .SYNOPSIS
        True for the self-signed certificate Hyper-V puts in the Root store of the machine for connections to virtual machines.
    .DESCRIPTION
        Recognized by everything at once: machine store, issuer and subject equal to the computer name, the Hyper-V
        extension, server authentication only, not a certificate authority, and Hyper-V installed.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param($Certificate, [string]$Store, [string]$ComputerName = $env:COMPUTERNAME, [bool]$HyperVInstalled)
    if (-not $Certificate -or -not $HyperVInstalled -or $Store -ne 'LocalMachine' -or -not $ComputerName) { return $false }
    $cn = "CN=$ComputerName"
    if ($Certificate.Subject -ne $cn -or $Certificate.Issuer -ne $cn) { return $false }
    $extensions = @($Certificate.Extensions)
    if (-not @($extensions | Where-Object { $_.Oid.Value -eq $script:ThemisHyperVCertOid }).Count) { return $false }
    $eku = @($extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if ($eku.Count -ne 1) { return $false }
    $uses = @($eku[0].EnhancedKeyUsages | ForEach-Object Value)
    if ($uses.Count -ne 1 -or $uses[0] -ne '1.3.6.1.5.5.7.3.1') { return $false }
    foreach ($constraint in @($extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })) { if ($constraint.CertificateAuthority) { return $false } }
    return $true
}

function Read-ThemisRootCertificatesFact {
    <#
    .SYNOPSIS
        Root certificates added outside those of Windows. Only reads: an antivirus root is reported, never removed.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $hyperV = [bool](Get-Service -Name vmms -ErrorAction SilentlyContinue)
    $found = foreach ($store in 'LocalMachine', 'CurrentUser') {
        $hive = if ($store -eq 'LocalMachine') { 'HKLM' } else { 'HKCU' }
        # The registry store itself: Cert:\...\Root also shows what Group Policy and the enterprise stores add.
        $thumbs = @(Invoke-ThemisSafe { Get-ChildItem -LiteralPath "${hive}:\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates" -ErrorAction Stop | ForEach-Object PSChildName } @())
        foreach ($thumb in $thumbs) {
            if ($thumb -in $script:ThemisBuiltinRoots) { continue }
            $cert = Get-Item -LiteralPath "Cert:\$store\Root\$thumb" -ErrorAction SilentlyContinue
            if (-not $cert) { continue }
            if (Test-ThemisHyperVRootCertificate -Certificate $cert -Store $store -HyperVInstalled $hyperV) { continue }
            $name = (($cert.Subject -split ',\s*(?=[A-Z]+=)') | Where-Object { $_ -match '^(CN|OU|O|E)=' } | Select-Object -First 1) -replace '^(CN|OU|O|E)=', ''
            [pscustomobject]@{ Store = $store; Thumbprint = $thumb; Name = $name; Subject = $cert.Subject; NotAfter = $cert.NotAfter; Antivirus = (Test-ThemisAntivirusRoot -Subject $cert.Subject) }
        }
    }
    $found = @($found)
    return @{ AddedRootCertificates = $found; NoAddedRootCerts = (@($found | Where-Object { -not $_.Antivirus }).Count -eq 0) }
}

function Read-ThemisFactSource {
    <#
    .SYNOPSIS
        Reads one source of facts (cached for the run) and returns its facts.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory = $true)][string]$Source)
    $key = "Facts:$Source"
    if ($script:ThemisRunCache.ContainsKey($key)) { return $script:ThemisRunCache[$key] }
    $facts = @{}
    if ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop') {
        $facts = switch ($Source) {
            'OS' { Read-ThemisOSFact }
            'Firmware' { Read-ThemisFirmwareFact }
            'DeviceGuard' { Read-ThemisDeviceGuardFact }
            'BitLocker' { Read-ThemisBitLockerFact }
            'Antivirus' { Read-ThemisAntivirusFact }
            'Updates' { Read-ThemisUpdatesFact }
            'SmartAppControl' { Read-ThemisSmartAppControlFact }
            'Accounts' { Read-ThemisAccountsFact }
            'Dns' { Read-ThemisDnsFact }
            'Devices' { Read-ThemisDevicesFact }
            'Drivers' { Read-ThemisDriversFact }
            'Services' { Read-ThemisServicesFact }
            'Console' { Read-ThemisConsoleFact }
            'RootCertificates' { Read-ThemisRootCertificatesFact }
            default { throw "Unknown fact source '$Source'." }
        }
        if ($facts -isnot [hashtable]) { $facts = @($facts | Where-Object { $_ -is [hashtable] }) | Select-Object -Last 1 }
        if ($null -eq $facts) { $facts = @{} }
    }
    $script:ThemisRunCache[$key] = $facts
    return $facts
}

function Get-ThemisFactName {
    <#
    .SYNOPSIS
        Names of the facts the rules use: their AppliesIf conditions and the Fact of Check rules.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([object[]]$Rules)
    $names = foreach ($rule in @($Rules | Where-Object { $_ })) {
        $conditions = $rule.AppliesIf
        if ($conditions -is [System.Collections.IDictionary]) { $conditions.Keys }
        elseif ($conditions) { $conditions.PSObject.Properties.Name }
        if ($rule.Fact) { "$($rule.Fact)" }
    }
    return [string[]]@($names | Where-Object { $_ } | Select-Object -Unique)
}

function Resolve-ThemisFact {
    <#
    .SYNOPSIS
        The facts for a run: those the caller gave, plus the built-in facts the rules use and the caller did not give.
    .DESCRIPTION
        Facts given by the caller always win. Only the sources of the missing facts are read, once per run.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param($Facts, [object[]]$Rules, [switch]$NoCollection)
    $merged = @{}
    if ($Facts -is [System.Collections.IDictionary]) { foreach ($k in $Facts.Keys) { $merged["$k"] = $Facts[$k] } }
    elseif ($Facts) { foreach ($p in $Facts.PSObject.Properties) { $merged[$p.Name] = $p.Value } }
    if ($NoCollection) { return $merged }
    foreach ($name in Get-ThemisFactName -Rules $Rules) {
        if ($merged.ContainsKey($name) -or -not $script:ThemisFactCatalog.Contains($name)) { continue }
        $source = Read-ThemisFactSource -Source $script:ThemisFactCatalog[$name].Source
        $merged[$name] = $source[$name]
    }
    return $merged
}
