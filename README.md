<div align="center">

# GSecurity

Windows hardening toolkit with unattended installation, policy enforcement, and local security scripts.

[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg)](https://www.microsoft.com/windows)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Stars](https://img.shields.io/github/stars/DumDumTras/GSecurity)](https://github.com/DumDumTras/GSecurity/stargazers)
[![Issues](https://img.shields.io/github/issues/DumDumTras/GSecurity)](https://github.com/DumDumTras/GSecurity/issues)

[Overview](#overview) • [Quick Start](#quick-start) • [Scripts](#scripts) • [Structure](#structure) • [Safety Notes](#safety-notes)

</div>

---

## Overview

GSecurity is a Windows hardening bundle designed for unattended installs and post-install lockdown. It ships with scripts for service disabling, registry policies (including browser policies), credential protections, basic antivirus behavior for unsigned DLLs, and a game caching system for performance.

What it provides:
- Unattended Windows install via `Iso/AutoUnattend.xml`
- Post-install script runner via `SetupComplete.cmd`
- System hardening via `GSecurity.bat`
- Browser policy enforcement and certificate removals via `GSecurity.reg`
- Credential protections via `Creds.ps1`
- Privilege rights hardening via `Secpol.ps1`
- Simple antivirus behavior for unsigned DLLs via `Antivirus.ps1`
- Game file caching via `GameCache.ps1`

---

## Quick Start

### Option A: Build an ISO (recommended)

1. Copy Windows installation files into `Iso/`.
2. Edit `Iso/AutoUnattend.xml` to set your product key and preferences.
3. Build a bootable ISO using your preferred tool (Oscdimg, ImgBurn, etc.).
4. Install Windows from the ISO. First logon runs `GSecurity.bat` via setup commands.

### Option B: Harden an existing system

```powershell
git clone https://github.com/DumDumTras/GSecurity.git
cd GSecurity
```

```cmd
cd Iso\sources\$OEM$\$$\Setup\Scripts
SetupComplete.cmd
```

---

## Scripts

### `SetupComplete.cmd`
- Elevates privileges
- Imports all `.reg` files in the `Bin` folder (alphabetical)
- Designed as the main setup entry point

### `GSecurity.bat`
- Runs all `.reg` and `.ps1` files in `Bin`
- Applies system hardening (permissions, service disables, DoT, UAC)
- Reboots after completion

### `GSecurity.reg`
- Enforces browser policies (Chrome, Edge, Firefox, Brave, Vivaldi, Arc, Zen)
- Forces extension installs and privacy settings
- Removes selected root certificates and adds disallowed certs

### `Creds.ps1`
- Enables LSASS PPL
- Clears cached credentials
- Disables credential caching
- Enables audit policy for credential validation

### `Secpol.ps1`
- Applies privilege-rights restrictions via `secedit`

### `Antivirus.ps1` (Simple Antivirus)
- Scans for unsigned DLLs and WINMD files
- Quarantines suspicious files to `C:\Quarantine`
- Uses file system watchers for near real-time detection
- Logs to `C:\Quarantine\antivirus_log.txt`

### `GameCache.ps1`
- Multi-tier caching system using RAM and SSD
- Uses symlinks for transparent access
- Runs as a scheduled task on startup
- Logs to `C:\ProgramData\GameCache\cache.log`

---

## Configuration

### Unattended Install
Edit `Iso/AutoUnattend.xml` to update:
- Product key
- Time zone and locale
- Auto-logon user
- OEM info and first-logon commands

### GameCache
Edit the configuration block in `GameCache.ps1`:
- RAM/SSD cache size
- Target game directories
- Cache intervals and file extensions

### Antivirus
`Antivirus.ps1` uses:
- Quarantine location: `C:\Quarantine`
- Local hash database: `C:\Quarantine\scanned_files.txt`
- Log file: `C:\Quarantine\antivirus_log.txt`

---

## Structure

```
GSecurity/
├── Iso/
│   ├── Autorun.ico
│   ├── Autorun.inf
│   ├── AutoUnattend.xml
│   └── sources/
│       └── $OEM$/
│           ├── $$/
│           │   └── Setup/
│           │       └── Scripts/
│           │           ├── SetupComplete.cmd
│           │           └── Bin/
│           │               ├── Antivirus.ps1
│           │               ├── Creds.ps1
│           │               ├── GameCache.ps1
│           │               ├── Secpol.ps1
│           │               ├── GSecurity.bat
│           │               └── GSecurity.reg
│           └── $1/
│               ├── autoexec.bat
│               ├── config.sys
│               └── users/
│                   └── Default/
│                       └── Desktop/
│                           └── Extras/
│                               └── BrowserInstallers/
└── README.md
```

---

## Safety Notes

- This project makes aggressive system changes. Test in a VM first.
- Services are disabled (remote access, file sharing, WinRM, etc.).
- Permissions are modified on system files and user folders.
- Certificate removals can break apps and websites.
- Auto-logon is enabled in `AutoUnattend.xml` by default.
- GameCache requires administrator privileges to create symlinks.

---

## License

No license file is included in this repository. Add one if you intend to distribute.

---

## Support

Issues and feature requests: https://github.com/DumDumTras/GSecurity/issues
