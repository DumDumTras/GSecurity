# Simple Antivirus
# Author: Gorstak

# Unique script identifier (GUID) - used for process identification and mutex naming
$Script:ScriptGUID = "539EF6B5-578B-46F3-A5C7-FD564CB9C8FB"

# Define paths and parameters
$taskName = "SimpleAntivirusStartup"
$taskDescription = "Runs the Simple Antivirus script at user logon with admin privileges."
$quarantineFolder = "C:\Quarantine"
$logFile = "$quarantineFolder\antivirus_log.txt"
$localDatabase = "$quarantineFolder\scanned_files.txt"
$scannedFiles = @{}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-Elevation {
    param([string]$Reason = "This operation requires administrator privileges.")
    
    $mutexName = "Global\AntivirusProtection_$Script:ScriptGUID"
    
    if (Test-IsAdmin) {
        # We're admin - try to claim the mutex
        $script:ElevationMutex = New-Object System.Threading.Mutex($false, $mutexName)
        try {
            $owned = $script:ElevationMutex.WaitOne(0)
            if (-not $owned) {
                # Another elevated instance already running
                Write-Host "Another elevated instance is already running. Exiting."
                exit
            }
        } catch {
            # Mutex already exists and held
            Write-Host "Another elevated instance is already running. Exiting."
            exit
        }
        return $true
    }
    
    # Not admin - check if elevated instance exists
    try {
        $mutex = New-Object System.Threading.Mutex($false, $mutexName)
        $hasHandle = $mutex.WaitOne(0, $false)
        if ($hasHandle) {
            $mutex.ReleaseMutex()
            $mutex.Dispose()
        } else {
            # Elevated instance running - exit this one
            Write-Host "Elevated instance already running. Exiting."
            exit
        }
    } catch {
        # Mutex held - elevated instance exists
        Write-Host "Elevated instance already running. Exiting."
        exit
    }
    
    # Need to elevate
    Write-Warning $Reason
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

function Install-Antivirus {
    # Copy script to quarantine folder
    $targetPath = "$quarantineFolder\Antivirus.ps1"
    if ($PSCommandPath -ne $targetPath) {
        Copy-Item -Path $PSCommandPath -Destination $targetPath -Force -ErrorAction SilentlyContinue
        Write-Log "Installed script to $targetPath"
    }
    
    # Add to HKCU Run key for current user startup
    $runKeyPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $runKeyName = "SimpleAntivirus"
    $runCommand = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetPath`""
    
    try {
        Set-ItemProperty -Path $runKeyPath -Name $runKeyName -Value $runCommand -ErrorAction Stop
        Write-Log "Added to startup: $runKeyName"
    } catch {
        Write-Log "Failed to add to startup: $($_.Exception.Message)"
    }
}

# Logging Function with Rotation
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $message"
    Write-Host "Logging: $logEntry"
    if (-not (Test-Path $quarantineFolder)) {
        New-Item -Path $quarantineFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Host "Created folder: $quarantineFolder"
    }
    if ((Test-Path $logFile) -and ((Get-Item $logFile -ErrorAction SilentlyContinue).Length -ge 10MB)) {
        $archiveName = "$quarantineFolder\antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        Rename-Item -Path $logFile -NewName $archiveName -ErrorAction Stop
        Write-Host "Rotated log to: $archiveName"
    }
    $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8 -ErrorAction Stop
}

# Take Ownership and Modify Permissions (Aggressive)
function Set-FileOwnershipAndPermissions {
    param ([string]$filePath)
    try {
        takeown /F $filePath /A | Out-Null
        icacls $filePath /reset | Out-Null
        icacls $filePath /grant "Administrators:F" /inheritance:d | Out-Null
        Write-Log "Forcibly set ownership and permissions for $filePath"
        return $true
    } catch {
        Write-Log "Failed to set ownership/permissions for ${filePath}: $($_.Exception.Message)"
        return $false
    }
}

# Calculate File Hash and Signature
function Calculate-FileHash {
    param ([string]$filePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        Write-Log "Signature status for ${filePath}: $($signature.Status) - $($signature.StatusMessage)"
        return [PSCustomObject]@{
            Hash = $hash.Hash.ToLower()
            Status = $signature.Status
            StatusMessage = $signature.StatusMessage
        }
    } catch {
        Write-Log "Error processing ${filePath}: $($_.Exception.Message)"
        return $null
    }
}

# Quarantine File
function Quarantine-File {
    param ([string]$filePath)
    try {
        $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath (Split-Path $filePath -Leaf)
        Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
        Write-Log "Quarantined file: $filePath to $quarantinePath"
    } catch {
        Write-Log "Failed to quarantine ${filePath}: $($_.Exception.Message)"
    }
}

# Stop Processes Using DLL
function Stop-ProcessUsingDLL {
    param ([string]$filePath)
    try {
        $processes = Get-Process | Where-Object { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) }
        foreach ($process in $processes) {
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
            Write-Log "Stopped process $($process.Name) (PID: $($process.Id)) using $filePath"
        }
    } catch {
        Write-Log "Error stopping processes for ${filePath}: $($_.Exception.Message)"
        try {
            $processes = Get-Process | Where-Object { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) }
            foreach ($process in $processes) {
                taskkill /PID $process.Id /F | Out-Null
                Write-Log "Force-killed process $($process.Name) (PID: $($process.Id)) using taskkill"
            }
        } catch {
            Write-Log "Fallback process kill failed for ${filePath}: $($_.Exception.Message)"
        }
    }
}

function Is-SuspiciousElfFile {
    param ([string]$filePath)
    $fileName = [System.IO.Path]::GetFileName($filePath).ToLower()
    return $fileName -like '*_elf.dll'
}

function Should-ExcludeFile {
    param ([string]$filePath)
    $lowerPath = $filePath.ToLower()
    
    if ($lowerPath -like "*\assembly\*") {
        Write-Log "Excluding assembly folder file: $filePath"
        return $true
    }
    
    if ($lowerPath -like "*ctfmon*" -or $lowerPath -like "*msctf.dll" -or $lowerPath -like "*msutb.dll") {
        Write-Log "Excluding ctfmon-related file: $filePath"
        return $true
    }
    
    return $false
}

# Remove Unsigned DLLs
function Remove-UnsignedDLLs {
    Write-Log "Starting unsigned DLL/WINMD scan."
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
    foreach ($drive in $drives) {
        $root = $drive.DeviceID + "\"
        Write-Log "Scanning drive: $root"
        try {
            $dllFiles = Get-ChildItem -Path $root -Include *.dll,*.winmd -Recurse -File -Exclude @($quarantineFolder, "C:\Windows\System32\config") -ErrorAction Stop
            foreach ($dll in $dllFiles) {
                try {
                    if (Should-ExcludeFile -filePath $dll.FullName) {
                        continue
                    }
                    
                    if (Is-SuspiciousElfFile -filePath $dll.FullName) {
                        Write-Log "Detected ELF file (quarantine regardless of signature): $($dll.FullName)"
                        if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                            Stop-ProcessUsingDLL -filePath $dll.FullName
                            Quarantine-File -filePath $dll.FullName
                        }
                        continue
                    }
                    
                    $fileHash = Calculate-FileHash -filePath $dll.FullName
                    if ($fileHash) {
                        if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                            Write-Log "Skipping already scanned file: $($dll.FullName) (Hash: $($fileHash.Hash))"
                            if (-not $scannedFiles[$fileHash.Hash]) {
                                if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                    Stop-ProcessUsingDLL -filePath $dll.FullName
                                    Quarantine-File -filePath $dll.FullName
                                }
                            }
                        } else {
                            $isValid = $fileHash.Status -eq "Valid"
                            $scannedFiles[$fileHash.Hash] = $isValid
                            "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction Stop
                            Write-Log "Scanned new file: $($dll.FullName) (Valid: $isValid)"
                            if (-not $isValid) {
                                if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                    Stop-ProcessUsingDLL -filePath $dll.FullName
                                    Quarantine-File -filePath $dll.FullName
                                }
                            }
                        }
                    }
                } catch {
                    Write-Log "Error processing file $($dll.FullName): $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Log "Scan failed for drive ${root} $($_.Exception.Message)"
        }
    }
    
    # Explicit System32 Scan
    Write-Log "Starting explicit System32 scan."
    try {
        $system32Files = Get-ChildItem -Path "C:\Windows\System32" -Include *.dll,*.winmd -File -ErrorAction Stop
        foreach ($dll in $system32Files) {
            try {
                if (Should-ExcludeFile -filePath $dll.FullName) {
                    continue
                }
                
                if (Is-SuspiciousElfFile -filePath $dll.FullName) {
                    Write-Log "Detected ELF file in System32 (quarantine regardless of signature): $($dll.FullName)"
                    if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                        Stop-ProcessUsingDLL -filePath $dll.FullName
                        Quarantine-File -filePath $dll.FullName
                    }
                    continue
                }
                
                $fileHash = Calculate-FileHash -filePath $dll.FullName
                if ($fileHash) {
                    if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                        Write-Log "Skipping already scanned System32 file: $($dll.FullName) (Hash: $($fileHash.Hash))"
                        if (-not $scannedFiles[$fileHash.Hash]) {
                            if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                Stop-ProcessUsingDLL -filePath $dll.FullName
                                Quarantine-File -filePath $dll.FullName
                            }
                        }
                    } else {
                        $isValid = $fileHash.Status -eq "Valid"
                        $scannedFiles[$fileHash.Hash] = $isValid
                        "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction Stop
                        Write-Log "Scanned new System32 file: $($dll.FullName) (Valid: $isValid)"
                        if (-not $isValid) {
                            if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                Stop-ProcessUsingDLL -filePath $dll.FullName
                                Quarantine-File -filePath $dll.FullName
                            }
                        }
                    }
                }
            } catch {
                Write-Log "Error processing System32 file $($dll.FullName): $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Log "System32 scan failed: $($_.Exception.Message)"
    }
}

# File System Watcher setup
function Setup-FileWatchers {
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
    foreach ($drive in $drives) {
        $monitorPath = $drive.DeviceID + "\"
        try {
            $fileWatcher = New-Object System.IO.FileSystemWatcher
            $fileWatcher.Path = $monitorPath
            $fileWatcher.Filter = "*.*"
            $fileWatcher.IncludeSubdirectories = $true
            $fileWatcher.EnableRaisingEvents = $true
            $fileWatcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite

            $action = {
                param($sender, $e)
                try {
                    if ($e.ChangeType -in "Created", "Changed" -and $e.FullPath -notlike "$quarantineFolder*" -and ($e.FullPath -like "*.dll" -or $e.FullPath -like "*.winmd")) {
                        if (Should-ExcludeFile -filePath $e.FullPath) {
                            return
                        }
                        
                        Write-Log "Detected file change: $($e.FullPath)"
                        
                        if (Is-SuspiciousElfFile -filePath $e.FullPath) {
                            Write-Log "Detected new ELF file (quarantine regardless of signature): $($e.FullPath)"
                            if (Set-FileOwnershipAndPermissions -filePath $e.FullPath) {
                                Stop-ProcessUsingDLL -filePath $e.FullPath
                                Quarantine-File -filePath $e.FullPath
                            }
                            return
                        }
                        
                        $fileHash = Calculate-FileHash -filePath $e.FullPath
                        if ($fileHash) {
                            if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                                Write-Log "Skipping already scanned file: $($e.FullPath) (Hash: $($fileHash.Hash))"
                                if (-not $scannedFiles[$fileHash.Hash]) {
                                    if (Set-FileOwnershipAndPermissions -filePath $e.FullPath) {
                                        Stop-ProcessUsingDLL -filePath $e.FullPath
                                        Quarantine-File -filePath $e.FullPath
                                    }
                                }
                            } else {
                                $isValid = $fileHash.Status -eq "Valid"
                                $scannedFiles[$fileHash.Hash] = $isValid
                                "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction Stop
                                Write-Log "Added new file to database: $($e.FullPath) (Valid: $isValid)"
                                if (-not $isValid) {
                                    if (Set-FileOwnershipAndPermissions -filePath $e.FullPath) {
                                        Stop-ProcessUsingDLL -filePath $e.FullPath
                                        Quarantine-File -filePath $e.FullPath
                                    }
                                }
                            }
                        }
                        Start-Sleep -Milliseconds 500
                    }
                } catch {
                    Write-Log "Watcher error for $($e.FullPath): $($_.Exception.Message)"
                }
            }

            Register-ObjectEvent -InputObject $fileWatcher -EventName Created -Action $action -ErrorAction Stop
            Register-ObjectEvent -InputObject $fileWatcher -EventName Changed -Action $action -ErrorAction Stop
            Write-Log "FileSystemWatcher set up for $monitorPath"
        } catch {
            Write-Log "Failed to set up watcher for ${monitorPath} $($_.Exception.Message)"
        }
    }
}

# ==================== MAIN EXECUTION ====================

# Request elevation (will exit and restart as admin if needed)
Request-Elevation -Reason "Antivirus protection requires administrator privileges for full functionality."

# Ensure quarantine folder exists
if (-not (Test-Path $quarantineFolder)) {
    New-Item -Path $quarantineFolder -ItemType Directory -Force | Out-Null
}

# Initial log
$isAdmin = Test-IsAdmin
Write-Log "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
    Write-Log "Set execution policy to Bypass for current user."
}

# Load scanned files database
if (Test-Path $localDatabase) {
    try {
        $scannedFiles.Clear()
        $lines = Get-Content $localDatabase -ErrorAction Stop
        foreach ($line in $lines) {
            if ($line -match "^([0-9a-f]{64}),(true|false)$") {
                $scannedFiles[$matches[1]] = [bool]::Parse($matches[2])
            }
        }
        Write-Log "Loaded $($scannedFiles.Count) scanned file entries from database."
    } catch {
        Write-Log "Failed to load database: $($_.Exception.Message)"
        $scannedFiles.Clear()
    }
} else {
    $scannedFiles.Clear()
    New-Item -Path $localDatabase -ItemType File -Force -ErrorAction Stop | Out-Null
    Write-Log "Created new database: $localDatabase"
}

# Install to quarantine folder and add to startup
Install-Antivirus

# Run initial scan
Remove-UnsignedDLLs

# Setup file watchers for real-time protection
Setup-FileWatchers

# Keep script running
Write-Host "Antivirus running. Press [Ctrl] + [C] to stop."
try {
    while ($true) { Start-Sleep -Seconds 10 }
} catch {
    Write-Log "Main loop ended: $($_.Exception.Message)"
}
finally {
    # Cleanup mutex on exit
    if ($script:ElevationMutex) {
        try {
            $script:ElevationMutex.ReleaseMutex()
            $script:ElevationMutex.Dispose()
        } catch {}
    }
    Write-Log "Antivirus stopped."
}
