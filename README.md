# ThemisRules

[![CI](https://github.com/damdavidprieto/ThemisRules/actions/workflows/ci.yml/badge.svg)](https://github.com/damdavidprieto/ThemisRules/actions/workflows/ci.yml)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/ThemisRules.svg)](https://www.powershellgallery.com/packages/ThemisRules)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Audit and harden Windows with JSON policies. ThemisRules ships a ready-to-use **Windows workstation
baseline** (164 rules in three levels) and lets you write your own policies with the same rule types.

```powershell
Install-Module ThemisRules -Scope CurrentUser

# In an elevated session: how does this machine compare with the L1 baseline?
Invoke-ThemisPolicy -Baseline Windows-Workstation -MacroLevel L1 |
    Export-ThemisReport -Path .\workstation-L1.html
```

- **19 rule types**: registry values, services, optional features, advanced audit policy, password and
  lockout policy, user rights, firewall profiles and rules, Microsoft Defender settings and attack surface
  reduction, DNS over HTTPS, AppLocker, scheduled tasks, root certificates, event log sizes, local group members,
  protected folders, file signatures, processes and manual checks.
- **Facts about the machine**: Secure Boot, BitLocker, memory integrity, the antivirus, the last security update
  and 35 more, read by Themis itself for conditions (`AppliesIf`) and checks (`Get-ThemisFact`).
- **Exceptions and severities**: accepted deviations with a reason and an end date are `Excepted`, and reports
  give a score weighted by severity.
- **Audit or Enforce**: check only, or apply the expected configuration. `-WhatIf` and `-Confirm`
  work with Enforce.
- **Hardening levels L1 to L5**: `-MacroLevel L1` evaluates only the rules up to L1.
- **Reports**: one result per rule, and `Export-ThemisReport` writes JSON, CSV or HTML with a
  compliance score.
- **Safe rules**: every value from a policy is validated before it is used, and Enforce reads the
  value back to confirm the change (Group Policy can override local settings). Core Windows processes
  (`lsass`, `winlogon`, `csrss`, `services`...) cannot be named in a process rule.
- **Safe reports**: CSV values that start with `=`, `+`, `-` or `@` are written with a leading apostrophe,
  so a spreadsheet does not run them as formulas.
- Windows PowerShell 5.1 and PowerShell 7 on Windows. No dependencies. Every command has full help:
  `Get-Help Invoke-ThemisPolicy -Full`.

## The Windows workstation baseline

`Baselines/Windows-Workstation.json` collects security settings that the
[Microsoft Security Baselines](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
and the [CIS Benchmarks for Windows](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
commonly recommend, for Windows 10 and 11:

| Area | Examples | Rules |
|---|---|---|
| User Account Control and logon | Admin Approval Mode, secure desktop, inactivity lock, no automatic logon, no MPR notifications, sudo off | 10 |
| Credentials | No WDigest plain-text passwords, NTLMv2 only, no LM hashes, no anonymous enumeration, NTLM auditing, LSA protection, memory integrity and a check that Credential Guard runs (L2) | 13 |
| Kerberos | AES only, no DES or RC4 | 1 |
| Printing | Only administrators install printer drivers; Redirection Guard and RPC over TCP (L2) | 3 |
| Network | SMBv1 off, SMB signing, SMB failed-logon delay, LLMNR off, NetBIOS P-node (L2) | 7 |
| Remote access | RDP with NLA and high encryption, no Remote Assistance, WinRM without Basic or unencrypted traffic | 8 |
| Malware entry points | AutoPlay and AutoRun off, no elevated MSI installs, Defender PUA blocking, SmartScreen, Windows Script Host off (L3) | 7 |
| Logging | Command line in process events, PowerShell script block logging, transcription (L2), event log sizes | 7 |
| Advanced audit policy | Logon, credential validation, account and group management, process creation, policy changes, removable storage... | 21 |
| Password and lockout policy | 14+ characters, history of 24, complexity, lockout after 1 to 10 attempts, Guest disabled | 11 |
| Windows Firewall | All three profiles on, inbound blocked by default, dropped-packet logging (L2) | 15 |
| Services | Remote Registry, UPnP/SSDP (L2), Internet Connection Sharing (L2), Print Spooler and WebClient (L3) | 6 |
| Privacy | Diagnostic data limited to required (L2) | 1 |
| User rights assignment | Nobody may act as part of the OS or create tokens; debug, drivers, backup and restore for Administrators only; Guests denied every logon type; local accounts denied network and RDP logons (L2) | 32 |
| Microsoft Defender | Real-time, behavior, download and script scanning on; removable drives and email scanned; cloud protection and samples; attack surface reduction: LSASS, vulnerable drivers and WMI persistence (L1), Office, script and USB rules (L2); network protection (L2) | 22 |

- **L1** (120 rules): safe for any machine.
- **L2** (41): stronger; may affect compatibility or convenience (for example LSA protection and
  third-party authentication plug-ins, Office attack surface reduction rules, or user rights that
  SQL Server and IIS add for their own accounts).
- **L3** (3): high security; turns features off (Windows Script Host, printing, WebDAV).

Every rule has an ID, a name and, where useful, a description of why it matters. Registry rules
whose documented Windows default already meets the rule declare it with `Default`, so a value that
is simply not set is not reported as a problem.

```powershell
Get-ThemisBaseline                                    # name, version, rules per level
Invoke-ThemisPolicy -Baseline Windows-Workstation     # audit every level
Invoke-ThemisPolicy -Baseline Windows-Workstation -MacroLevel L1 -Mode Enforce -WhatIf   # preview
Invoke-ThemisPolicy -Baseline Windows-Workstation -MacroLevel L1 -Mode Enforce -Confirm  # apply, rule by rule
```

Run it in an elevated session: audit and security policy rules need administrator rights (without
them they are reported as errors that say so). On domain-joined machines Group Policy usually
defines these settings; use the baseline to audit them and change them in Group Policy. To adapt
the baseline, copy it and edit the copy:

```powershell
Copy-Item (Get-ThemisBaseline -Name Windows-Workstation).Path .\my-baseline.json
Invoke-ThemisPolicy -PolicyPath .\my-baseline.json
```

## Writing a policy

```powershell
New-ThemisPolicy -Path .\baseline.json -Name 'Workstation baseline'
```

A policy is a JSON file with a `Meta` section and one array per rule type:

```json
{
  "Meta": { "Name": "Example", "Version": "1.0.0" },
  "RegistryRules": [
    { "ID": "REG-1", "MacroLevel": "L1", "Name": "SMB signing required", "Type": "DWord",
      "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
      "ValueName": "RequireSecuritySignature", "Value": 1 },
    { "ID": "REG-2", "MacroLevel": "L1", "Name": "Security log 192 MB or more", "Type": "DWord",
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security",
      "ValueName": "MaxSize", "Value": 196608, "Comparison": "AtLeast" }
  ],
  "AuditPolicyRules": [
    { "ID": "AUD-1", "MacroLevel": "L1", "Name": "Audit Logon",
      "Subcategory": "{0CCE9215-69AE-11D9-BED3-505054503030}", "Setting": "SuccessAndFailure" }
  ],
  "SecurityPolicyRules": [
    { "ID": "ACC-1", "MacroLevel": "L1", "Name": "Lockout after 1 to 10 attempts",
      "Key": "LockoutBadCount", "Value": 10, "Comparison": "Between", "Min": 1, "Max": 10 }
  ],
  "FirewallProfileRules": [
    { "ID": "FW-1", "MacroLevel": "L1", "Name": "Public profile on", "Profile": "Public", "Setting": "Enabled", "Value": "True" }
  ],
  "ServiceRules": [
    { "ID": "SVC-1", "MacroLevel": "L1", "Name": "RemoteRegistry", "State": "Stopped", "StartupType": "Disabled" }
  ],
  "ProcessRules": [
    { "ID": "PRC-1", "MacroLevel": "L3", "Name": "notepad", "State": "Absent" }
  ]
}
```

| Section | Fields | Notes |
|---|---|---|
| `RegistryRules` | `Path`, `ValueName`, `Value`, `Type` (`DWord`, `QWord`, `String`, `ExpandString`, `MultiString`, `Binary`), optional `Default`, `WriteValue`, `Ensure` (`Absent`) with `MatchValue` | `Path` must be a registry path; a `*` in its last segment checks every matching subkey (none is `NotApplicable`). `WriteValue` is what Enforce writes when it differs from `Value` (needed for `Between` and `In`). `Ensure = Absent` removes the value, or with `MatchValue` only that value. DWORD and QWORD values are compared as unsigned numbers. |
| `AuditPolicyRules` | `Subcategory` (GUID), `Setting` (`Success`, `Failure`, `SuccessAndFailure`, `NoAuditing`) | GUIDs, because subcategory names depend on the Windows language: `auditpol /list /subcategory:* /v`. Auditing more than required is compliant. |
| `UserRightsRules` | `Right` (such as `SeDebugPrivilege`), `Principals` (SIDs), `Comparison` (`Equal`, `Includes`, `Excludes`) | SIDs, because account names depend on the Windows language: `S-1-5-32-544` is Administrators. `Equal` with no principals means nobody. |
| `SecurityPolicyRules` | `Key`, `Value` (whole number) | `[System Access]` keys of the local security policy: password and lockout settings, Guest and Administrator accounts, anonymous name lookup. |
| `FirewallProfileRules` | `Profile` (`Domain`, `Private`, `Public`), `Setting`, `Value` | Settings: `Enabled`, `DefaultInboundAction`, `DefaultOutboundAction`, `AllowInboundRules`, `AllowLocalFirewallRules`, `AllowUnicastResponseToMulticast`, `NotifyOnListen`, `LogBlocked`, `LogAllowed`, `LogMaxSizeKilobytes`. Backups keep `NotConfigured` for settings that were not set locally. |
| `ServiceRules` | `Name` and any of `State` (`Running`, `Stopped`), `StartupType` (`Automatic`, `Manual`, `Disabled`), `AllowStricter`, `Action` (`Absent`) | A service that is not installed meets rules that want it stopped or disabled. `AllowStricter` accepts a stricter startup type (`Disabled` meets `Manual`). Enforcing `Disabled` also stops the service unless the rule sets `State`; protected services that refuse `Set-Service` are changed with `sc.exe`. `Absent` deletes the service in Enforce mode. |
| `FeatureRules` | `Feature` (such as `SMB1Protocol`), `State` (`Enabled`, `Disabled`) | Windows optional features. A feature this Windows does not include is `NotApplicable`. Needs elevation. |
| `SecureFolderRules` | `Path` (absolute), `Sddl` (permissions, such as `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`), or `Ensure` (`Absent`) | Creates the folder with exactly those permissions (only the DACL is written). `Absent` gives it its parent's permissions back and removes it only if it is empty. |
| `LocalGroupMemberRules` | `Group` (SID), `Member` (SID), `Ensure` (`Present`, `Absent`) | Direct membership of an account in a local group, such as `S-1-5-32-573` (Event Log Readers). SIDs, because group names depend on the Windows language. Reading works without elevation; changing needs it, and the account gets the new membership at its next sign-in. |
| `EventLogRules` | `LogName`, `MaxSizeMB`, `Exact` | Maximum size of an event log, such as `Microsoft-Windows-PowerShell/Operational`. A larger log is compliant unless `Exact`. A log this Windows does not have is `NotApplicable`. Changing the size needs elevation. |
| `CheckRules` | `Fact`, `Expected`, optional `Action` | Something that has to be done by hand (Secure Boot, BitLocker...). A built-in fact is read by Themis (see *Facts about the machine*); others come from `-Facts`. A check that is not met is `Manual`, and Enforce never changes anything. |
| `DefenderPreferenceRules` | `Setting` and `Value`, or `AsrRule` (GUID) and `AsrAction` (`Block`, `Audit`, `Warn`, `Disabled`) | A Microsoft Defender setting (`PUAProtection`, `MAPSReporting`, `EnableNetworkProtection`, `DisableRealtimeMonitoring`...) or one attack surface reduction rule, read and changed with `Get-MpPreference` and `Set-MpPreference`. These are the values Defender really uses: a change that Tamper Protection or a Group Policy keeps from happening is `EnforceFailed`. `NotApplicable` when another antivirus is the active one. Needs elevation to change. |
| `DnsOverHttpsRules` | `ServerAddress`, `Template`, `AllowFallbackToUdp` (default false), `AutoUpgrade` (default true), `Ensure` | The DNS over HTTPS template of one DNS server (Windows 11), so Windows encrypts the queries to it. Whether every configured server has one is the `DnsEncrypted` fact. Needs elevation to change. |
| `ProcessRules` | `Name`, `State` (`Absent`, `Present`) | `Absent` stops the process in Enforce mode. |
| `ScheduledTaskRules` | `TaskPath`, `TaskName`, `Ensure` (`Disabled`, `Enabled`, `Absent`, `Present`), `Xml` | Disables, enables or removes a scheduled task. A missing task counts as disabled. Removing records the task definition, so the restore rule registers it again exactly as it was. |
| `FirewallRuleRules` | `DisplayName`, `Program`, `Direction` (`Outbound`), `Action` (`Block`), `Ensure` | A firewall rule for one program, for example blocking outbound connections of `mshta.exe`. Themis only touches rules in its own group, `ThemisRules`. Needs elevation. |
| `RootCertificateRules` | `Thumbprint`, `Store` (`LocalMachine`, `CurrentUser`), `Ensure` (`Absent`, `Present`), `RawData` | Whether a certificate is trusted as a root. Removing one records the certificate, so the restore rule adds back the same one; a restore rule cannot add a certificate other than the one its thumbprint names. |
| `FileSignatureRules` | `Path`, `Publisher`, `AllowMissing` | A file must have a valid signature, optionally from one publisher. Enforce cannot fix it: a file that does not comply is `Manual`. |
| `AppLockerRules` | `Collection` (`Exe`, `Script`, `Msi`, `Dll`, `Appx`), `Mode` (`AuditOnly`, `Enabled`, `NotConfigured`), `DefaultRules`, `AllowPublishers`, `AllowPaths`, `AllowPathExceptions` | One AppLocker rule collection. The standard rules let everyone run what is in the Windows and Program Files folders, and administrators anything; programs and scripts in Downloads, Temp or inside a `.zip` are not allowed. `AllowPathExceptions` leaves paths out of the `AllowPaths` rules: allowing `%OSDRIVE%\Users\*` except Downloads and Temp keeps the programs installed in user folders working and blocks what is downloaded. Start with `AuditOnly`: Windows logs what would be blocked in `Microsoft-Windows-AppLocker/*` without blocking it. Themis owns the rules named `Themis: ...` and keeps the others. AppLocker only acts while the Application Identity service (`AppIDSvc`) runs. Needs elevation. |

Every rule takes `ID`, `Name` and optionally `MacroLevel` (`L1`-`L5`), `Description`, `Severity` (`Low`, `Medium`,
`High` or `Critical`; `Medium` when not given) and `References` (benchmark IDs or documentation addresses). Values can
use `Comparison`: `Equal` (default), `AtLeast`, `AtMost`, `Between` (with `Min` and `Max`) or `In`
(`Value` is a list); Enforce writes `Value`, or `WriteValue` when given. Any rule can set `RequiresRestart` when its
change only takes effect after a restart.

`Test-ThemisPolicy -Path .\policy.json` lists the problems of a policy: fields the schema does not know (usually a
typo, with a "did you mean" hint), missing required fields and sections no provider handles. `Invoke-ThemisPolicy
-Strict` runs it first and refuses a policy with problems.
### Conditions and dependencies

Any rule can take `AppliesIf`, conditions on facts about the machine that you pass with `-Facts`, and
`DependsOn`, the IDs of rules earlier in the policy:

```json
{ "ID": "SVC-2", "Name": "Spooler", "StartupType": "Disabled",
  "AppliesIf": { "HasPrinters": false, "OSBuild": { "ge": 22000 } } },
{ "ID": "REG-9", "Name": "Transcripts folder", "DependsOn": [ "DIR-1" ], "...": "..." }
```

```powershell
Invoke-ThemisPolicy -PolicyPath .\policy.json -Facts @{ HasPrinters = $false; OSBuild = 26100 }
```

A condition is a value (equal; text without case) or a comparison (`lt`, `le`, `gt`, `ge`, `eq`,
`ne`). When one is not met, or the fact is not known, the rule is `NotApplicable` and nothing is
read or changed.

### Facts about the machine

Themis reads the built-in facts that the rules of a run use and `-Facts` does not give, once per run and only
from the sources needed. Nothing is changed. `-Facts` always wins, and `-NoFactCollection` turns the reading off.

```powershell
Get-ThemisFact -Name SecureBootOn, BitLockerSystemDrive, HvciRunning, UpdatesRecent
Get-ThemisFact -ListAvailable | Format-Table Name, Description
```

| Source | Facts |
|---|---|
| Windows | `OSBuild`, `OSName`, `DisplayVersion`, `IsElevated`, `UserIsAdministrator`, `DomainJoined`, `IsLaptop` |
| Firmware | `UefiFirmware`, `SecureBootOn`, `SecureBootCertsUpdated` (2023 certificates), `TpmPresent` |
| Device Guard | `VbsCapable`, `VbsRunning`, `HvciRunning`, `CredentialGuardRunning`, `KernelDmaProtection`, `HasDmaPorts` |
| BitLocker | `BitLockerSystemDrive`, `BitLockerStartupPin` (needs elevation) |
| Antivirus | `AntivirusHealthy`, `AntivirusStatus`, `ThirdPartyAntivirus`, `DefenderActive`, `DefenderMode` |
| Updates | `LastSecurityUpdateDays`, `UpdatesRecent` (40 days) |
| Smart App Control | `SmartAppControlState`, `SmartAppControlOn` |
| Accounts | `AllAccountsHavePassword`, `AccountsWithoutPassword` |
| DNS | `DnsServers`, `DnsEncrypted` (every server has a DNS over HTTPS template) |
| Devices | `HasPrinters`, `HasBluetooth`, `HasCamera`, `HasMicrophone`, `HasWifi`, `HasSmbShares` |
| Drivers | `HwAccessDrivers`, `NoHwAccessDrivers` (drivers that tools and malware use to reach memory and ports) |
| Services | `UnsignedSystemServices`, `SystemServicesSigned` (services running as SYSTEM a program without a valid signature) |

A fact that cannot be read (it needs elevation, or this Windows does not have it) is `$null`: a check on it is
`Unknown`.

### Exceptions

An accepted deviation is not a failure: list it with a reason, and optionally an end date and who accepted it.

```json
{ "Exceptions": [
    { "ID": "WIN-SVC-005", "Reason": "The office printer needs the spooler", "Owner": "IT", "Until": "2027-06-30" }
] }
```

```powershell
Invoke-ThemisPolicy -Baseline Windows-Workstation -Exceptions .\exceptions.json
```

A rule with a valid exception that does not comply is `Excepted` (its reason says why and until when), Enforce
leaves it as it is, and reports leave it out of the scores. After `Until` the exception is ignored, with a
warning, and the rule counts again. A rule whose dependency is not applicable, failed, or in Enforce mode is still not
compliant is `Skipped`, so a setting is never applied half way.

### One rule at a time

Tools that keep their own history can use `Invoke-ThemisRule`, which evaluates a single rule:

```powershell
$r = Invoke-ThemisRule -Type Service -Rule @{ ID = 'SVC-1'; Name = 'RemoteRegistry'; StartupType = 'Disabled' } -Mode Enforce
$r.Data        # what was read, as structured values (here Status and StartType)
$r.Previous    # restore rules: pass each back with -Mode Enforce to undo the change
```

It returns the same result as each rule of `Invoke-ThemisPolicy` plus `Data`, `Previous` and
`Condition` (the condition that was not met), and saves no backup: the caller keeps `Previous`.

Several rules can go through the pipeline at once, as objects with `Type` and `Rule`. They share one read of the
security policy, the audit policy and the facts, and each result is available to the next rules for `DependsOn`:

```powershell
$rules | ForEach-Object { @{ Type = $_.Type; Rule = $_ } } | Invoke-ThemisRule
``` The schema is in
[`Schema/ThemisPolicy.schema.json`](Schema/ThemisPolicy.schema.json) and there are small example
policies in [`Examples/`](Examples/).

A policy is code you run with administrator rights: only run policies you wrote or got from a source
you trust, and keep them where only administrators can edit them. Every rule is checked before it
runs: registry rules must point at the registry, service and process rules need an exact name (no
wildcards), security policy keys come from a fixed list and take whole numbers only, and audit
subcategories must be GUIDs.

## Undoing an Enforce run

Before Enforce changes anything it records the previous value. When at least one rule is changed it
saves them as a backup (a policy that puts them back) and adds its path to every changed result:

```powershell
$results = Invoke-ThemisPolicy -Baseline Windows-Workstation -MacroLevel L1 -Mode Enforce
Get-ThemisBackup                                    # newest first: time, policy, values, path
Get-ThemisBackup | Select-Object -First 1 | Restore-ThemisBackup -WhatIf   # preview
Get-ThemisBackup | Select-Object -First 1 | Restore-ThemisBackup           # undo
```

Backups cover registry values (including removing values that did not exist), service state and
startup type, audit policy, password and lockout settings, user rights and firewall settings. Stopped
processes and deleted services cannot be restored. The backup is updated after every changed rule,
so a run that stops halfway can still be undone.

Backups go to `ThemisRules\Backups` under `%ProgramData%` in an elevated session, a folder that only
SYSTEM and Administrators can change, and under `%LOCALAPPDATA%` otherwise. Use `-BackupPath` to choose
another folder, or `-NoBackup` to skip them. A backup is a policy that runs as administrator when you
restore it, so in an elevated session `Restore-ThemisBackup` refuses a file that users without
elevation could have edited (for example one in `%LOCALAPPDATA%` or in a `-BackupPath` folder): review
it and copy it into the protected folder first. `-WhatIf` previews any backup. Every backup also records the hash
of its content (`Meta.ContentHash`), and `Restore-ThemisBackup` refuses one that was edited after it was saved,
wherever it is.

`Invoke-ThemisPolicy -Mode Enforce -RollbackOnFailure` applies a policy whole or not at all: if a change fails, the
changes of that run are undone, newest first, the remaining rules are not run, and the undone results get
`RolledBack = $true`.

To see what changed after you applied a policy, compare the two runs:

```powershell
$applied = Invoke-ThemisPolicy -PolicyPath .\policy.json -Mode Enforce
Compare-ThemisResult -Reference $applied -Difference (Invoke-ThemisPolicy -PolicyPath .\policy.json) |
    Where-Object Change -eq 'Drifted'
```
## Results

```text
Timestamp   : 2026-11-14 21:00:00
Policy      : Windows workstation baseline
PolicyPath  : C:\...\ThemisRules\1.3.0\Baselines\Windows-Workstation.json
ID          : WIN-ACC-003
Type        : SecurityPolicy
Name        : Minimum password length: 14 characters or more
MacroLevel  : L1
Status      : Non-Compliant
IsCompliant : False
Reason      : MinimumPasswordLength is 8; required: 14 or more.
Actual      : 8
```

Every result has `Severity`, `References` and `Exception`. `Export-ThemisReport` gives the compliance score, a
score weighted by severity (Low 1, Medium 2, High 3, Critical 4) and the rules that do not comply by severity.

Status values: `Compliant`, `Non-Compliant`, `Fixed`, `Excepted`, `MissingKey`, `MissingValue`, `MissingService`,
`EnforceFailed` (the change did not take effect, usually because Group Policy defines the value),
`NotApplicable` (its `AppliesIf` is not met, or the item does not exist on this machine),
`NeedsElevation` (it can only be read as administrator), `Manual` (a check that has to be fixed by
hand), `Unknown` (a check whose fact was not given), `Skipped` (a `DependsOn` rule is not ready) and
`Error` (invalid rule or a failed read).

Every changed rule is read again after Enforce: `Verified` is `$true` when the change shows, `$false` when it does
not (a policy or a protection may undo it, or it needs a restart). `RequiresRestart` says whether the change needs
a restart, and `Restorable` whether the provider returned how to undo it.
## Development

```powershell
./build.ps1 -InstallDependencies   # once: Pester 5 and PSScriptAnalyzer
./build.ps1                        # analysis + tests + build into output/ThemisRules
```

The repository follows the layout of the [Sampler](https://github.com/gaelcolas/Sampler) module
template: the package is built from the runtime files only, and the QA tests check that every
command has complete help, that the code passes PSScriptAnalyzer with
[`PSScriptAnalyzerSettings.psd1`](PSScriptAnalyzerSettings.psd1) (including Windows PowerShell 5.1
compatibility) and that the changelog is up to date. The provider tests mock `auditpol`, `secedit`
and the firewall cmdlets; the CI workflow runs the baseline audit tests on its hosted Windows runner, which runs with administrator rights, on Windows PowerShell 5.1 and PowerShell 7, and installs the built package with `Install-Module`. Pushing a `v*` tag
publishes the version to the PowerShell Gallery.

See [CONTRIBUTING](.github/CONTRIBUTING.md), [SECURITY](SECURITY.md) and the [changelog](CHANGELOG.md).

## License

[MIT](LICENSE) © 2026 David Prieto
