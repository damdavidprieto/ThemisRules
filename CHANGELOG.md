# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.0] - 2026-11-14

### Security
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
- `Get-ThemisProviders` is now `Get-ThemisProvider` (singular noun); the old name remains as an alias.
- Policies are read as UTF-8 on Windows PowerShell 5.1.
- `New-ThemisPolicy` no longer adds an empty `WMIRules` section, which has no provider and made every
  new policy print a warning. `WMIRules` was also removed from the schema.
- Example policies: `FullStack_Policy.json` is now `Workstation_Baseline.json` and no longer deletes the
  DiagTrack service (it stops and disables it); `Gaming_Optimization.json` no longer has `WMIRules` and
  `ScriptRules` sections, which no provider handles. The tests audit both examples.
- Every exported command has complete help with examples.
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
