# ThemisRules

**JSON policy engine for Windows compliance auditing and enforcement.**

[![CI](https://github.com/damdavidprieto/ThemisRules/actions/workflows/ci.yml/badge.svg)](https://github.com/damdavidprieto/ThemisRules/actions/workflows/ci.yml)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/ThemisRules.svg)](https://www.powershellgallery.com/packages/ThemisRules)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

You describe the desired state of a machine in a JSON policy (registry values, services,
processes). ThemisRules checks each rule, reports what complies and what does not, and in
`Enforce` mode fixes what it can.

## Features

- **Registry, Service and Process rules**, each handled by a provider in `Providers/`.
- **Audit or Enforce**: check only, or apply the expected configuration.
- **Hardening levels (L1-L5)**: `-MacroLevel L2` evaluates only rules up to L2.
- **Results with metadata**: policy name and path, timestamp, status, reason and actual value per rule.
- **Reports**: `Export-ThemisReport` writes JSON, CSV or HTML with a compliance score.
- **Windows PowerShell 5.1 and PowerShell 7**, no dependencies.

## Installation

```powershell
Install-Module ThemisRules -Scope CurrentUser
```

The module auto-loads the first time you call one of its commands.

## Quick start

```powershell
# Create an empty policy and add rules to it
New-ThemisPolicy -Path .\baseline.json -Name "Workstation baseline"

# Audit every rule
Invoke-ThemisPolicy -PolicyPath .\baseline.json -Mode Audit

# Audit only L1 rules and save an HTML report
Invoke-ThemisPolicy -PolicyPath .\baseline.json -MacroLevel L1 | Export-ThemisReport -Path .\report.html

# Apply the L1 rules (run elevated for HKLM and services)
Invoke-ThemisPolicy -PolicyPath .\baseline.json -Mode Enforce -MacroLevel L1
```

`Enforce` changes the system: registry values are written, services are started, stopped,
reconfigured or **deleted** (`"Action": "Absent"`), and processes are stopped. Run `Audit` first.

A policy is code you run with administrator rights: only run policies you wrote or got from a source
you trust, and keep them where only administrators can edit them. Every rule is checked before it runs:
registry rules must point at the registry (`HKLM:`, `HKCU:`, `Registry::...`), and service and process
rules need an exact name. Wildcards such as `*` are rejected, so one rule cannot stop every process or
delete every service.

## Policy format

```json
{
  "Meta": { "Name": "System Security", "Version": "1.0.0" },
  "RegistryRules": [
    {
      "ID": "SYS-UAC-001",
      "MacroLevel": "L1",
      "Name": "UAC consent prompt",
      "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
      "ValueName": "ConsentPromptBehaviorAdmin",
      "Value": 2,
      "Type": "DWord"
    }
  ],
  "ServiceRules": [
    { "ID": "SVC-001", "MacroLevel": "L2", "Name": "SysMain", "State": "Stopped", "StartupType": "Disabled" }
  ],
  "ProcessRules": [
    { "ID": "PRC-001", "MacroLevel": "L3", "Name": "notepad", "State": "Absent" }
  ]
}
```

| Section | Fields |
|---|---|
| `RegistryRules` | `Path`, `ValueName`, `Value`, `Type` (`DWord`, `QWord`, `String`, `MultiString`) |
| `ServiceRules` | `Name` and any of `State` (`Running`, `Stopped`), `StartupType` (`Automatic`, `Manual`, `Disabled`), `Action` (`Absent`) |
| `ProcessRules` | `Name`, `State` (`Absent`, `Present`) |

Every rule takes `ID`, `Name` and optionally `MacroLevel` (`L1`-`L5`) and `Description`.
The full schema is in [`Schema/ThemisPolicy.schema.json`](Schema/ThemisPolicy.schema.json) and there are
sample policies in [`Examples/`](Examples/). `Get-ThemisProviders` lists the rule sections the installed version supports.

## Result format

```text
Timestamp   : 2026-11-13 21:00:00
Policy      : System Security
PolicyPath  : C:\Policies\system_security.json
ID          : SYS-UAC-001
Type        : Registry
Name        : UAC consent prompt
MacroLevel  : L1
Status      : Compliant
IsCompliant : True
Reason      : Value matches expected configuration.
Actual      : 2
```

Status values: `Compliant`, `Non-Compliant`, `Fixed`, `MissingKey`, `MissingValue`, `MissingService`,
`EnforceFailed`, `Error`.

## Hardening levels

| Level | Intended for |
|---|---|
| **L1** | Baseline for every machine |
| **L2** | Power users, stronger privacy |
| **L3** | High-security environments |
| **L4** | Maximum isolation |
| **L5** | Monitoring and forensic settings |

Rules without `MacroLevel` are always evaluated.

## Development

```powershell
./build.ps1 -InstallDependencies   # once: Pester 5 and PSScriptAnalyzer
./build.ps1                        # analysis + tests + build into output/ThemisRules
```

CI runs the tests on PowerShell 7 and Windows PowerShell 5.1 and installs the built package with
`Install-Module`. Releases are published from `output/ThemisRules` by the `Publish` workflow when a
`v*` tag is pushed. See the [changelog](CHANGELOG.md).

## License

[MIT](LICENSE) © 2026 David Prieto
