# Simple Antivirus
# Author: Gorstak

function Register-SystemLogonScript {
    param ([string]$TaskName = "SimpleAntivirus")

    $scriptSource = $MyInvocation.MyCommand.Path
    if (-not $scriptSource) { $scriptSource = $PSCommandPath }
    if (-not $scriptSource) {
        Write-Host "Error: Could not determine script path."
        return
    }

    $targetFolder = "C:\ProgramData\SimpleAntivirus"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Host "Created folder: $targetFolder"
    }

    try {
        Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
        Write-Host "Copied script to: $targetPath"
    } catch {
        Write-Host "Failed to copy script: $_"
        return
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Host "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
    } catch {
        Write-Host "Failed to register task: $_"
    }
}

# Run the function
Register-SystemLogonScript

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

Watch-NewBinaries

Write-Host "`nMonitoring active. Press Ctrl+C to stop.`n" -ForegroundColor Magenta

while ($true) {
    Wait-Event -Timeout 5 | Out-Null
    if ($global:removables.Count -gt 0) {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Pending removables: $($global:removables.Count)" -ForegroundColor Gray
    }
}
