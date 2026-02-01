# ThemisRules Engine

**ThemisRules** is a professional Validation Engine for PowerShell, designed to enforce business logic, data integrity, and policy compliance through a flexible **Provider-based Architecture**.

It allows you to define rules decoupled from your business logic, making your code cleaner, testable, and easier to maintain.

## 🚀 Features

- **Provider Architecture**: Extensible design to support multiple validation sources.
- **Policy/Rule Separation**: Define complex policies composed of reusable granular rules.
- **Fluent API**: Easy to read and write validation logic.
- **Integration Ready**: Designed to work seamlessly with `ArgosCCF` and `HermesConsoleUI`.

## 📦 Installation

```powershell
Install-Module -Name ThemisRules
```

## ⚡ Quick Start

```powershell
Import-Module ThemisRules

# Example usage (Conceptual)
$policy = New-ThemisPolicy -Name "UserValidation" -Rules {
    Rule "PasswordStrength" -On "Password" -Must { $_.Length -gt 8 }
    Rule "EmailFormat" -On "Email" -Must { $_ -match "^[^@]+@[^@]+\.[^@]+$" }
}

Invoke-ThemisPolicy -Policy $policy -InputObject $userData
```

## 🏗️ Architecture

ThemisRules is built on three core pillars:
1.  **Core**: The central engine that processes rules.
2.  **Providers**: Plugins that define *how* rules are evaluated (e.g., ScriptBlock, Regex, External API).
3.  **Public API**: Clean cmdlets for end-users (`New-ThemisPolicy`, `Invoke-ThemisPolicy`).

## 🤝 Contributing

Contributions are welcome! Please submit a Pull Request or open an Issue.

## 📄 License

This project is licensed under the **MIT License**.
