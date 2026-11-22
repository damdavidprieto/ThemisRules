# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.0] - 2026-11-22

ThemisRules can now be the engine of a hardening tool that keeps its own history and user interface,
such as Cassiel.

### Added
- **`Invoke-ThemisRule`**: evaluates or applies a single rule and returns, besides the usual result,
  `Data` (what was read, as structured values), `Previous` (restore rules for what Enforce changed) and
  `Condition` (the AppliesIf condition that was not met). It saves no backup: the caller keeps `Previous`.
  `-KeepReadCache` reuses the exported security and audit policy across calls of one audit.
- **`-Facts`, `AppliesIf` and `DependsOn`**: rules can depend on facts about the machine (values or
  numeric comparisons) and on earlier rules. New statuses `NotApplicable` and `Skipped`.
- **`FeatureRules`** (Windows optional features), **`SecureFolderRules`** (a folder with exact
  permissions; undoing removes it only if empty) and **`CheckRules`** (manual actions, status `Manual`).
- **Registry**: a `*` in the last path segment checks every matching subkey; `Comparison = In`;
  `WriteValue`; `Ensure = Absent` with `MatchValue`; `ExpandString` values kept unexpanded; undoing a
  change removes the key it created when it is left empty.
- **Services**: `AllowStricter` (Disabled meets Manual); protected services are changed with `sc.exe`
  when `Set-Service` is refused.
- **Firewall**: `AllowInboundRules`, `AllowLocalFirewallRules` and `AllowUnicastResponseToMulticast`.
- Status `NeedsElevation` for values that can only be read as administrator.

### Changed
- Audit policy, security policy and user rights rules report `NeedsElevation` instead of `Error`
  without elevation, and so do optional features and unreadable registry keys.
- DWORD and QWORD registry values are compared as unsigned numbers: `0xFFFFFFFF` is 4294967295, not -1.
- Enforcing a service `StartupType` of `Disabled` also stops the service, unless the rule sets `State`.
- Firewall backups record the local setting, so one that was `NotConfigured` goes back to that.
- Registry rules are read back after Enforce: a value that Group Policy puts back is `EnforceFailed`.
- Previous values (backups) cover exactly what changed: a write that fails changes nothing and adds
  nothing to undo, and a registry rule that fails halfway returns the keys it did change.

### Security
- **Windows tools are called by full path.** `auditpol`, `secedit` and `sc` were run by bare name, so
  PowerShell looked in the current folder and the `PATH` first; in an elevated session a program planted
  there with the same name would have run as administrator. They now run from the System32 folder.
- **Backups cannot be edited without elevation.** Elevated runs save backups under
  `%ProgramData%\ThemisRules\Backups`, owned by Administrators and changeable only by SYSTEM and
  Administrators; a folder created there beforehand by another user is taken over. In an elevated
  session `Restore-ThemisBackup` refuses a backup that users without elevation could change, because
  restoring it writes its values as administrator. `-WhatIf` still previews any backup. Backups made
  before this version are in `%LOCALAPPDATA%`; review one and copy it to the new folder to restore it
  elevated.

### Fixed
- **A run that stops halfway can be undone.** The backup was written once, after every rule had run, so
  an error, Ctrl+C or a power cut lost the previous values of what had already changed. It is now
  updated after every changed rule, written to a temporary file and moved into place.
- **Partly applied changes are kept in the backup.** Providers record the previous value before
  changing anything. A service whose startup type changed but that then failed to start reported an
  error and kept nothing to restore; it now reports `EnforceFailed` and its old startup type and state
  are in the backup.
- **Service rules are checked after Enforce.** The provider assumed every change worked; it now reads
  the service again and reports `EnforceFailed` when it is not as the rule requires.
- **`-MacroLevel` skipped rules without a level**, although the help says they are always evaluated.
  They are now evaluated; a rule whose level is not L1 to L5 is skipped with a warning.
- **Two runs in the same second wrote the same backup file.** Names now include milliseconds and a
  random suffix.

## [1.3.0] - 2026-11-14

### Security
- **CSV injection.** `Export-ThemisReport -Format Csv` wrote values such as `=HYPERLINK(...)` as they
  were, and a spreadsheet would run them as formulas. Values that start with `=`, `+`, `-`, `@`, a tab or a
  carriage return now get a leading apostrophe.
- **Core Windows processes.** A process rule could name `lsass`, `winlogon`, `csrss`, `services` and
  similar, and Enforce would stop them. These names are now refused in every mode.
- **Registry rules could write outside the registry.** `Path` was passed straight to `New-Item` and
  `Set-ItemProperty`, so a policy could point it at the file system and `Enforce` would create files or
  change file attributes. Paths must now resolve to the registry provider and are used literally.
- **Wildcards in service and process names.** `Get-Service`, `Get-Process` and `Stop-Process` treat
  names as patterns, so a rule named `*` with `"Action": "Absent"` or `"State": "Absent"` would delete
  every service or stop every process in `Enforce` mode. Names with wildcard characters are now rejected.
- **Provider spoofing.** Any function in the session named `Invoke-Themis*Rule` was registered as a
  provider. Only the module's own providers are registered now.
- `Enforce` reported `Fixed` when starting or stopping a service, stopping a process or deleting a
  service had failed. Failures are now reported as `Error` or `EnforceFailed`.

### Added
- **Windows workstation baseline** (`Baselines/Windows-Workstation.json`): 150 rules in levels L1 (111),
  L2 (36) and L3 (3), covering User Account Control, credential protection, SMB and name resolution,
  Remote Desktop and WinRM, malware entry points, logging, advanced audit policy, password and lockout
  policy, user rights assignment, Microsoft Defender and attack surface reduction, Windows Firewall
  profiles, services and diagnostic data. Run it with
  `Invoke-ThemisPolicy -Baseline Windows-Workstation`; `Get-ThemisBaseline` lists the shipped baselines.
- **Undo**: Enforce records the previous value of every rule it changes and saves them as a backup
  policy. `Get-ThemisBackup` lists the backups and `Restore-ThemisBackup` puts the values back
  (stopped processes and deleted services excepted). `-BackupPath` and `-NoBackup` control it.
- **User rights assignment**: `UserRightsRules` check and set who holds each right, by SID (independent
  of the Windows language), with `Equal`, `Includes` and `Excludes`.
- **New rule types**: `AuditPolicyRules` (advanced audit policy subcategories by GUID, independent of
  the Windows language), `SecurityPolicyRules` (password, lockout and account settings of the local
  security policy) and `FirewallProfileRules` (Domain, Private and Public profile settings).
- **Comparisons**: numeric rules accept `Comparison` = `AtLeast`, `AtMost` or `Between` (with `Min` and
  `Max`), for settings such as minimum password length or event log size.
- Registry rules accept `Default`, the value Windows uses when the setting is not present; when it
  meets the rule, a missing value is compliant instead of reported.
- `Invoke-ThemisPolicy -Mode Enforce` supports `-WhatIf` and `-Confirm`: declined rules, or all rules with
  `-WhatIf`, are only audited.
- `New-ThemisPolicy -Force`; without it an existing file is not replaced. It also supports `-WhatIf`.

### Fixed
- **The module exported no functions.** 1.2.0 imported its engine and providers as separate global
  modules, so `Invoke-ThemisPolicy` did not belong to ThemisRules and the manifest filtered everything
  out. All files are now loaded into the module's own scope and it exports `Invoke-ThemisPolicy`,
  `Export-ThemisReport`, `Get-ThemisProviders` and `New-ThemisPolicy`.
- `Export-ThemisReport` was listed in the manifest but did not exist. Added: JSON, CSV and HTML
  reports with a compliance score.
- `Get-ThemisProviders` guessed providers from a hard-coded list; it now reads the registered ones.
- Rule sections with no provider are reported with a warning instead of being skipped silently.
- Metadata: author, copyright (MIT, matching `LICENSE`), project and license URLs. The 1.2.0 package
  pointed to a GitHub organisation that does not exist.

### Changed
- Minimum version: Windows PowerShell 5.1. Works on PowerShell 7.
- Pester tests for the manifest, auditing, `-MacroLevel` filtering, enforcement (on Pester's
  temporary `TestRegistry:` drive) and reports. CI runs them on PowerShell 7 and Windows
  PowerShell 5.1 and installs the built package with `Install-Module`.
- `build.ps1` builds `output/ThemisRules` with only the module files; the `Publish` workflow
  publishes that folder. Removed `ThemisRules.nuspec` and `Tools/publish_module.ps1`, which took
  the Gallery API key as a parameter and published the repository root.
- README describes the providers that exist (Registry, Service, Process).
- Enforce reads registry, audit policy, security policy and firewall values back after changing them;
  if Group Policy keeps the old value the rule is `EnforceFailed` instead of `Fixed`.
- A service that is not installed now meets rules that want it stopped or disabled.
- `Get-ThemisProviders` is now `Get-ThemisProvider` (singular noun); the old name remains as an alias.
- Policies are read as UTF-8 on Windows PowerShell 5.1.
- `New-ThemisPolicy` no longer adds an empty `WMIRules` section, which has no provider and made every
  new policy print a warning. `WMIRules` was also removed from the schema.
- Example policies: `FullStack_Policy.json` is now `Workstation_Baseline.json` and no longer deletes the
  DiagTrack service (it stops and disables it); `Gaming_Optimization.json` no longer has `WMIRules` and
  `ScriptRules` sections, which no provider handles. The tests audit both examples.
- Every exported command has complete help with examples.
- `Invoke-ThemisPolicy -Parallel` is removed: it never did anything. Scripts that pass it get a parameter error.
- Build and CI follow the structure of the Sampler module template: `PSScriptAnalyzerSettings.psd1`
  (Windows PowerShell 5.1 and PowerShell 7 compatibility rules), QA tests for help, analyzer,
  changelog and manifest, and a `Publish` workflow that also creates the GitHub release.

## [1.2.0] - 2026-02-08

### Added
- `-MacroLevel` filtering (L1-L5) in `Invoke-ThemisPolicy`.
- Policy name, path and timestamp in each result.

### Fixed
- Provider loading in some PowerShell environments, registry path validation, rules without
  `MacroLevel`, null references in result processing.

## [1.1.0] - 2026-02-01

- First release on the PowerShell Gallery: provider architecture with Registry, Service and Process rules.
