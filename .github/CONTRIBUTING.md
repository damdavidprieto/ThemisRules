# Contributing

Thanks for helping improve ThemisRules. Issues and pull requests are welcome. For security problems,
use the private channel in [SECURITY.md](../SECURITY.md) instead of an issue.

## Setting up

```powershell
git clone https://github.com/damdavidprieto/ThemisRules.git
cd ThemisRules
.\build.ps1 -InstallDependencies   # Pester 5 and PSScriptAnalyzer, first time only
.\build.ps1                        # analysis, tests and package
```

`build.ps1` must pass on both Windows PowerShell 5.1 and PowerShell 7 before a pull request is merged;
CI checks both. ThemisRules manages the Windows registry and services, so its tests that touch the
system only run on Windows (enforcement tests use Pester's temporary `TestRegistry:` drive).

## Making a change

- **New command:** add it to `Public/`, then to `FunctionsToExport` in `ThemisRules.psd1`
  and to `Export-ModuleMember` in `ThemisRules.psm1`. The QA tests fail if the lists differ. Use an
  approved verb (`Get-Verb`) and a singular noun; keep an alias when renaming.
- **Help:** every exported command needs comment-based help with a synopsis, a description, an
  example and a description for each parameter (`Tests/QA/Module.Tests.ps1` checks it).
- **Analyzer:** the code must have no findings with `PSScriptAnalyzerSettings.psd1`. If a rule does not
  apply, suppress it on that function with `SuppressMessageAttribute` and a justification.
- **Baselines:** rules in `Baselines/` need an ID, a level and, when it is not obvious, a `Description`
  of why the setting matters. Only add `Default` when the Windows default is documented. The tests
  audit every baseline on the CI runner (elevated) and check the audit subcategory GUIDs exist.
- **New rule type:** add a provider `Invoke-Themis<Type>Rule` in `Providers/` that takes `-Rule` and
  `-Mode` and returns Status, IsCompliant, Reason and Actual. Validate every value from the policy
  before it is used (paths, names, wildcards, allowed keys): policies run with administrator rights.
  Keep calls to system tools (auditpol, secedit, cmdlets) in small wrappers in `Core/Themis.Common.ps1`
  so the tests can mock them. Add the
  section to `Schema/ThemisPolicy.schema.json` and the README.
- **Encoding:** read and write files with `-Encoding UTF8`, and save source files that contain
  non-ASCII characters as UTF-8 with BOM, or Windows PowerShell 5.1 will misread them.
- **Tests:** add or update tests in `Tests/`. The example policies in `Examples/` are audited by the
  tests, so they may only use sections that have a provider.
- **Changelog:** describe the change under `## [Unreleased]` in `CHANGELOG.md`.

## Releasing

1. Move the `Unreleased` entries in `CHANGELOG.md` under the new version and update `ModuleVersion`
   in the manifest.
2. Push a tag `v<version>`. The `Publish` workflow checks that the tag matches the manifest, runs the
   build, publishes `output/ThemisRules` to the PowerShell Gallery and creates the GitHub release.
