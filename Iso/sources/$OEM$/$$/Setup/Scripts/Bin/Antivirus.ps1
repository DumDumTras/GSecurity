# Simple Antivirus
# Author: Gorstak


# Unique script identifier (GUID) - used for process identification and mutex naming
$Script:ScriptGUID = "539EF6B5-578B-49F3-A5C7-FD564CB9C8FB"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-Elevation {
    param([string]$Reason = "This operation requires administrator privileges.")
    
    $mutexName = "Global\SimpleAntivirus"
    
    if (Test-IsAdmin) {
        # Try to own the mutex (elevated parent holds it)
        $script:ElevationMutex = New-Object System.Threading.Mutex($false, $mutexName)
        try {
            $script:ElevationMutex.WaitOne(0) | Out-Null
        } catch {}
        return
    }
    
    # <CHANGE> Check if mutex exists (means elevated instance is running)
    $mutex = New-Object System.Threading.Mutex($false, $mutexName)
    $hasHandle = $false
    try {
        $hasHandle = $mutex.WaitOne(0, $false)
    } catch {}
    
    if (-not $hasHandle) {
        # Mutex held by elevated parent - we're a child, skip elevation
        return
    }
    
    # Release it - we're the first non-elevated instance, need to elevate
    $mutex.ReleaseMutex()
    $mutex.Dispose()
    
    Write-Warning $Reason
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Monitor for new DLL/WinMD files on all drives
function Watch-NewBinaries {
    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = "$($_.Root)"
        $watcher.Filter = "*.*"
        $watcher.IncludeSubdirectories = $true
        $watcher.EnableRaisingEvents = $true
        
        $action = {
            $path = $Event.SourceEventArgs.FullPath
            if ($path -match '\.(dll|winmd)$') {
                $sig = Get-AuthenticodeSignature $path
                if ($sig.Status -ne 'Valid') {
                    $global:removables += $path
                    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] UNSIGNED: $path" -ForegroundColor Red
                } else {
                    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Signed: $path" -ForegroundColor Green
                }
            }
        }
        
        Register-ObjectEvent $watcher Created -Action $action
        Write-Host "Watching: $($_.Root)" -ForegroundColor Cyan
    }
}

# Remove all permissions from $removables and *_elf.dll files
function Remove-BinaryPermissions {
    $targets = @($global:removables)
    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        $targets += Get-ChildItem -Path $_.Root -Recurse -Filter "*_elf.dll" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    }
    
    foreach ($file in $targets | Select-Object -Unique) {
        if (Test-Path $file) {
            $acl = New-Object System.Security.AccessControl.FileSecurity
            $acl.SetAccessRuleProtection($true, $false)
            Set-Acl -Path $file -AclObject $acl
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Permissions removed: $file" -ForegroundColor Yellow
        }
    }
}

# Initialize and run loop
$global:removables = @()
$flagFile = "$env:ProgramData\AntivirusProtection\.elevated"
Register-EngineEvent PowerShell.Exiting -Action { Remove-Item $flagFile -Force -ErrorAction SilentlyContinue } | Out-Null

Watch-NewBinaries

Write-Host "`nMonitoring active. Press Ctrl+C to stop.`n" -ForegroundColor Magenta

while ($true) {
    Wait-Event -Timeout 5 | Out-Null
    if ($global:removables.Count -gt 0) {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Pending removables: $($global:removables.Count)" -ForegroundColor Gray
    }
}
