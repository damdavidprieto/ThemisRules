# ThemisRules v1.2.0

**Universal Policy Engine for Security Auditing and Enforcement**

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/ThemisRules.svg)](https://www.powershellgallery.com/packages/ThemisRules)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## 🎯 Features

- ✅ **MacroLevel Filtering** - Native support for hierarchical security levels (L1-L5)
- ✅ **Policy Metadata** - Full audit trail with policy name, path, and timestamps
- ✅ **Multi-Provider** - Registry, Service, Feature, and extensible architecture
- ✅ **Audit & Enforce** - Check compliance or apply changes
- ✅ **JSON-Based Policies** - Easy to read, write, and version control

## 📦 Installation

```powershell
# Install from PowerShell Gallery
Install-Module ThemisRules -Scope CurrentUser

# Or update existing installation
Update-Module ThemisRules
```

## 🚀 Quick Start

### Basic Audit

```powershell
# Audit all rules in a policy
Invoke-ThemisPolicy -PolicyPath ".\system_security.json" -Mode Audit
```

### Level-Based Filtering

```powershell
# Only audit L1 rules (basic hardening)
Invoke-ThemisPolicy -PolicyPath ".\system_security.json" -Mode Audit -MacroLevel "L1"

# Audit L1 and L2 rules (advanced hardening)
Invoke-ThemisPolicy -PolicyPath ".\system_security.json" -Mode Audit -MacroLevel "L2"
```

### Enforcement

```powershell
# Apply L1 hardening
Invoke-ThemisPolicy -PolicyPath ".\system_security.json" -Mode Enforce -MacroLevel "L1"
```

## 📝 Policy Format

```json
{
  "Meta": {
    "Name": "System Security",
    "Version": "1.0.0"
  },
  "RegistryRules": [
    {
      "ID": "SYS-UAC-001",
      "MacroLevel": "L1",
      "Name": "UAC Consent Prompt",
      "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
      "ValueName": "ConsentPromptBehaviorAdmin",
      "Value": 2,
      "Type": "DWord",
      "Description": "Sets UAC to Always Notify"
    }
  ],
  "ServiceRules": [
    {
      "ID": "SVC-XBOX-001",
      "MacroLevel": "L3",
      "Name": "XblAuthManager",
      "Action": "Disable",
      "Description": "Disables Xbox Live services"
    }
  ]
}
```

## 🔍 Result Format

```powershell
Timestamp   : 2026-02-08 21:00:00
Policy      : System Security
PolicyPath  : C:\Policies\system_security.json
ID          : SYS-UAC-001
Type        : Registry
Name        : UAC Consent Prompt
MacroLevel  : L1
Status      : Compliant
IsCompliant : True
Reason      : Value matches expected configuration.
Actual      : 2
```

## 📊 MacroLevel Hierarchy

| Level  | Description    | Use Case                      |
| ------ | -------------- | ----------------------------- |
| **L1** | Standard       | Basic security for all users  |
| **L2** | Advanced       | Power users, enhanced privacy |
| **L3** | Bunker         | High-security environments    |
| **L4** | Singularity    | Maximum isolation             |
| **L5** | Active Defense | Forensic monitoring (T-POD)   |

## 🛠️ Supported Rule Types

- **Registry** - Windows Registry keys and values
- **Service** - Windows Services (start/stop/disable)
- **Feature** - Windows Optional Features

## 🔗 Integration Example (Cassiel)

```powershell
# Cassiel Security Framework integration
. "$PSScriptRoot\policy_engine.ps1"

$level = Get-ActiveHardeningLevel  # Returns "L1", "L2", etc.
$results = Invoke-CassielPolicy -PolicyName "system_security" -Mode "Audit" -MacroLevel $level

# Results are automatically filtered to active level
$score = ($results | Where-Object IsCompliant).Count / $results.Count * 100
Write-Host "Compliance Score: $score%"
```

## 📚 Documentation

- [Release Notes](RELEASE_NOTES_v1.2.0.md)
- [Examples](Examples/)

## 🤝 Contributing

ThemisRules is developed as part of the **Cassiel Security Framework**. Contributions welcome!

## 📄 License

Copyright (c) 2026 Cassiel Security. All rights reserved.

## 🔗 Links

- **PowerShell Gallery**: https://www.powershellgallery.com/packages/ThemisRules
- **GitHub**: https://github.com/damdavidprieto/ThemisRules

---

**Made with ❤️ by Cassiel Security Team**
