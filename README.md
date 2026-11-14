# ThemisRules

[![CI](https://github.com/damdavidprieto/ThemisRules/actions/workflows/ci.yml/badge.svg)](https://github.com/damdavidprieto/ThemisRules/actions/workflows/ci.yml)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/ThemisRules.svg)](https://www.powershellgallery.com/packages/ThemisRules)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Audit and harden Windows with JSON policies. ThemisRules ships a ready-to-use **Windows workstation
baseline** (99 rules in three levels) and lets you write your own policies with the same rule types.

```powershell
Install-Module ThemisRules -Scope CurrentUser

# In an elevated session: how does this machine compare with the L1 baseline?
Invoke-ThemisPolicy -Baseline Windows-Workstation -MacroLevel L1 |
    Export-ThemisReport -Path .\workstation-L1.html
```

- **Six rule types**: registry values, services, processes, advanced audit policy, password and
  lockout policy, and Windows Firewall profiles.
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
| User Account Control and logon | Admin Approval Mode, secure desktop, inactivity lock, no automatic logon | 8 |
| Credentials | No WDigest plain-text passwords, NTLMv2 only, no LM hashes, no anonymous enumeration, LSA protection (L2) | 9 |
| Network | SMBv1 off, SMB signing, LLMNR off, NetBIOS P-node (L2) | 6 |
| Remote access | RDP with NLA and high encryption, no Remote Assistance, WinRM without Basic or unencrypted traffic | 8 |
| Malware entry points | AutoPlay and AutoRun off, no elevated MSI installs, Defender PUA blocking, SmartScreen, Windows Script Host off (L3) | 7 |
| Logging | Command line in process events, PowerShell script block logging, transcription (L2), event log sizes | 7 |
| Advanced audit policy | Logon, credential validation, account and group management, process creation, policy changes, removable storage... | 21 |
| Password and lockout policy | 14+ characters, history of 24, complexity, lockout after 1 to 10 attempts, Guest disabled | 11 |
| Windows Firewall | All three profiles on, inbound blocked by default, dropped-packet logging (L2) | 15 |
| Services | Remote Registry, UPnP/SSDP (L2), Internet Connection Sharing (L2), Print Spooler and WebClient (L3) | 6 |
| Privacy | Diagnostic data limited to required (L2) | 1 |

- **L1** (77 rules): safe for any machine.
- **L2** (19): stronger; may affect compatibility or convenience (for example LSA protection and
  third-party authentication plug-ins).
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
| `RegistryRules` | `Path`, `ValueName`, `Value`, `Type` (`DWord`, `QWord`, `String`, `MultiString`), optional `Default` | `Path` must be a registry path. |
| `AuditPolicyRules` | `Subcategory` (GUID), `Setting` (`Success`, `Failure`, `SuccessAndFailure`, `NoAuditing`) | GUIDs, because subcategory names depend on the Windows language: `auditpol /list /subcategory:* /v`. Auditing more than required is compliant. |
| `SecurityPolicyRules` | `Key`, `Value` (whole number) | `[System Access]` keys of the local security policy: password and lockout settings, Guest and Administrator accounts, anonymous name lookup. |
| `FirewallProfileRules` | `Profile` (`Domain`, `Private`, `Public`), `Setting`, `Value` | Settings: `Enabled`, `DefaultInboundAction`, `DefaultOutboundAction`, `NotifyOnListen`, `LogBlocked`, `LogAllowed`, `LogMaxSizeKilobytes`. |
| `ServiceRules` | `Name` and any of `State` (`Running`, `Stopped`), `StartupType` (`Automatic`, `Manual`, `Disabled`), `Action` (`Absent`) | A service that is not installed meets rules that want it stopped or disabled. `Absent` deletes the service in Enforce mode. |
| `ProcessRules` | `Name`, `State` (`Absent`, `Present`) | `Absent` stops the process in Enforce mode. |

Every rule takes `ID`, `Name` and optionally `MacroLevel` (`L1`-`L5`) and `Description`. Numeric
values can use `Comparison`: `Equal` (default), `AtLeast`, `AtMost` or `Between` (with `Min` and
`Max`); Enforce writes `Value`. The schema is in
[`Schema/ThemisPolicy.schema.json`](Schema/ThemisPolicy.schema.json) and there are small example
policies in [`Examples/`](Examples/).

A policy is code you run with administrator rights: only run policies you wrote or got from a source
you trust, and keep them where only administrators can edit them. Every rule is checked before it
runs: registry rules must point at the registry, service and process rules need an exact name (no
wildcards), security policy keys come from a fixed list and take whole numbers only, and audit
subcategories must be GUIDs.

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

Status values: `Compliant`, `Non-Compliant`, `Fixed`, `MissingKey`, `MissingValue`, `MissingService`,
`EnforceFailed` (the change did not take effect, usually because Group Policy defines the value) and
`Error` (invalid rule, missing elevation or a failed read).

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
