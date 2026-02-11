# ThemisRules v1.2.0 - Release Notes

**Release Date**: 2026-02-08  
**Previous Version**: 1.1.0

## 🎯 New Features

### 1. MacroLevel Filtering Support (Post-Processing Workaround)

While ThemisRules doesn't natively support `-MacroLevel` parameter yet, Cassiel now implements post-processing filtering in `policy_engine.ps1` to filter results by hardening level.

**Impact**:

- ✅ Accurate compliance scoring per level
- ✅ Reduced false negatives in audits
- ✅ Better user experience

### 2. Enhanced Error Handling

- Improved provider loading error messages
- Better handling of missing registry keys
- More informative validation errors

## 🐛 Bug Fixes

### Registry Provider

- Fixed issue with provider module loading in certain PowerShell environments
- Improved path validation for registry keys

### Core Engine

- Better handling of rules without MacroLevel property
- Fixed null reference exceptions in result processing

## 📝 Documentation

- Added comprehensive enhancement request document
- Documented integration patterns with Cassiel
- Added examples for hierarchical policy evaluation

## 🔄 Breaking Changes

None - fully backward compatible with v1.1.0

## 📦 Installation

```powershell
# Update from PowerShell Gallery
Update-Module ThemisRules

# Or install fresh
Install-Module ThemisRules -Scope CurrentUser
```

## 🚀 Roadmap for v1.3.0

Based on Cassiel integration feedback:

1. Native `-MacroLevel` parameter support
2. Policy metadata in results
3. Undo/Rollback capabilities
4. Custom rule types (Firewall, File, WMI)

See `THEMIS_ENHANCEMENT_REQUEST.md` for full details.

---

**Full Changelog**: https://github.com/CassielSecurity/ThemisRules/compare/v1.1.0...v1.2.0
