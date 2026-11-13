# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-11-13

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

## [1.2.0] - 2026-02-08

### Added
- `-MacroLevel` filtering (L1-L5) in `Invoke-ThemisPolicy`.
- Policy name, path and timestamp in each result.

### Fixed
- Provider loading in some PowerShell environments, registry path validation, rules without
  `MacroLevel`, null references in result processing.

## [1.1.0] - 2026-02-01

- First release on the PowerShell Gallery: provider architecture with Registry, Service and Process rules.
