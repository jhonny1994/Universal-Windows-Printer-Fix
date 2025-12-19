<#
.SYNOPSIS
    Universal Windows Printer Fix (Global Production Release)
    Automates LTSC/22H2/24H2 Printer RPC, Discovery, and Legacy Remediation.

.DESCRIPTION
    A context-aware tool to fix Error 0x709, Access Denied, and Discovery issues.
    Features: OS Version Locking, Profile-Locked Security, and Legacy SMB1 Support.
    Authors: jhonny1994 (Core Logic) & Gemini AI (Refactoring)

.NOTES
    License:        MIT
    Supported OS:   Windows 10, Windows 11, Server 2016+ (Build 10240+)
    Min PowerShell: v5.1
#>

# 1. SELF-ELEVATION (RAM & FILE SAFE)
# --------------------------------------------------------
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Admin privileges required. Reloading..."
    
    if ($PSCommandPath) {
        # CASE A: Running from a physical file -> Relaunch the file
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    } else {
        # CASE B: Running from RAM (IRM) -> Relaunch the Download Command
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"irm https://raw.githubusercontent.com/jhonny1994/Universal-Windows-Printer-Fix/main/FixPrinters.ps1 | iex`"" -Verb RunAs
    }
    Exit
}

# 2. COMPATIBILITY GUARD (GLOBAL SAFETY CHECK)
# --------------------------------------------------------
$OSVersion = [System.Environment]::OSVersion.Version
$PSMajor   = $PSVersionTable.PSVersion.Major

# Guard 1: Block Windows 7, 8, 8.1 (Kernel < 10)
if ($OSVersion.Major -lt 10) {
    Write-Host "`n [CRITICAL ERROR] UNSUPPORTED OPERATING SYSTEM Detected." -ForegroundColor Red
    Write-Host " This script requires Windows 10 or Windows 11." -ForegroundColor White
    Write-Host " Execution Aborted to prevent system damage." -ForegroundColor Red
    Start-Sleep -Seconds 5
    Exit
}

# Guard 2: Block Old PowerShell (< 5.1)
if ($PSMajor -lt 5) {
    Write-Host "`n [CRITICAL ERROR] OUTDATED POWERSHELL DETECTED." -ForegroundColor Red
    Write-Host " This script requires PowerShell 5.1 or higher." -ForegroundColor White
    Start-Sleep -Seconds 5
    Exit
}

# 3. ENVIRONMENT SETUP
# --------------------------------------------------------
$ErrorActionPreference = "SilentlyContinue"
$Host.UI.RawUI.WindowTitle = "Universal Global Printer Fix"
$LogFile = "$env:TEMP\PrinterFix_Log_$(Get-Date -Format 'yyyyMMdd').txt"
$BackupDir = "$env:USERPROFILE\Desktop\Printer_Fix_Backups"

function Write-Log {
    param([string]$Type, [string]$Message)
    $LogEntry = "[{0}] [{1}] {2}" -f (Get-Date -Format "HH:mm:ss"), $Type, $Message
    Add-Content -Path $LogFile -Value $LogEntry
    switch ($Type) {
        "INFO"    { Write-Host " [INFO]    $Message" -ForegroundColor Cyan }
        "ACTION"  { Write-Host " [ACTION]  $Message" -ForegroundColor Green }
        "WARN"    { Write-Host " [WARN]    $Message" -ForegroundColor Yellow }
        "ERROR"   { Write-Host " [ERROR]   $Message" -ForegroundColor Red }
        Default   { Write-Host " $Message" }
    }
}

Clear-Host
$OSName = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Log "INFO" "Script Initialized."
Write-Log "INFO" "OS Verification Passed: $OSName"

# 4. USER MENU (NO ACTIONS YET)
# --------------------------------------------------------
Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "      UNIVERSAL GLOBAL PRINTER FIX" -ForegroundColor White
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " [1] HOST ONLY   :: This PC has the printer (Server)."
Write-Host " [2] CLIENT ONLY :: This PC connects to the printer."
Write-Host " [3] HYBRID/ALL  :: This PC does BOTH (Recommended)."
Write-Host ""
$Choice = Read-Host " Enter choice (1, 2, or 3)"

switch ($Choice) {
    "1" { $Role = "HOST" }
    "2" { $Role = "CLIENT" }
    "3" { $Role = "HYBRID" }
    Default { $Role = "HYBRID"; Write-Log "WARN" "Invalid input. Defaulting to HYBRID." }
}
Write-Log "INFO" "User Selected Role: $Role"

# 5. BACKUP ROUTINE (RUNS ONLY AFTER SELECTION)
# --------------------------------------------------------
Write-Host "`n [!] Creating Registry Backups..." -ForegroundColor Yellow
if (!(Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir | Out-Null }

try {
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\Print" "$BackupDir\Print_System_Backup.reg" /y | Out-Null
    reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "$BackupDir\Print_Policy_Backup.reg" /y | Out-Null
    Write-Log "INFO" "Registry Backup Saved to: $BackupDir"
} catch {
    Write-Log "WARN" "Backup failed. Proceeding with caution."
}

# 6. CORE FIXES (REGISTRY & PROTOCOLS)
# --------------------------------------------------------
Write-Host "`n [1/6] Applying Base Registry Protocols..." -ForegroundColor Magenta

function Set-RegKey {
    param($Path, $Name, $Value, $Type="DWord")
    if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

# Fix RPC Protocol & Privacy
Set-RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "RpcUseNamedPipeProtocol" 1
Set-RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "RpcProtocols" 0x7
Set-RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Print" "RpcAuthnLevelPrivacyEnabled" 0
Set-RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "RestrictDriverInstallationToAdministrators" 0
Write-Log "ACTION" "Optimized RPC & Driver Policies."

# 7. LEGACY SUPPORT (SMB 1.0)
# --------------------------------------------------------
Write-Host "`n [2/6] Checking Legacy Support (SMB 1.0)..." -ForegroundColor Magenta
$SMB1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
if ($SMB1.State -ne "Enabled") {
    Write-Log "ACTION" "Enabling SMB 1.0 (Legacy Support)..."
    Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
} else {
    Write-Log "INFO" "SMB 1.0 is already active."
}

# 8. HOST LOGIC
# --------------------------------------------------------
if ($Role -in "HOST", "HYBRID") {
    Write-Host "`n [3/6] Configuring HOST (Server) Settings..." -ForegroundColor Magenta
    
    # Allow Blank Passwords
    Set-RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse" 0
    
    # Enable Guest (SID Method)
    Get-LocalUser | Where-Object {$_.SID -like '*-501'} | Enable-LocalUser
    Write-Log "ACTION" "Enabled Guest Account (via SID)."

    # Force Private Network & Firewall
    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
    
    # Create Profile-Aware Firewall Rule (Only works on Win 10/11)
    New-NetFirewallRule -DisplayName 'Universal_Print_Fix_Ports' -Direction Inbound `
        -LocalPort 135,139,445 -Protocol TCP -Action Allow -Profile Private -Force | Out-Null
    Write-Log "ACTION" "Firewall Rules Set (Private Network Only)."

    # Discovery Services
    "fdPHost", "FDResPub", "SSDPSRV" | ForEach-Object {
        Set-Service -Name $_ -StartupType Automatic
        Start-Service -Name $_
    }
    Write-Log "ACTION" "Network Discovery Services Started."
}

# 9. CLIENT LOGIC
# --------------------------------------------------------
if ($Role -in "CLIENT", "HYBRID") {
    Write-Host "`n [4/6] Configuring CLIENT Settings..." -ForegroundColor Magenta

    # Allow Insecure Guest Auth
    Set-RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "AllowInsecureGuestAuth" 1
    Set-RegKey "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "AllowInsecureGuestAuth" 1
    
    # Force Private (Needed for Discovery)
    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private

    # Credential Cleanup (Strict Regex)
    Write-Log "ACTION" "Cleaning Stale Credentials..."
    net use * /delete /yes | Out-Null
    cmdkey /list | Select-String -Pattern 'Target:.*=(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.)' | ForEach-Object {
        $Target = $_.ToString().Split('=')[1]
        cmdkey /delete:$Target | Out-Null
        Write-Log "ACTION" "Removed Credential: $Target"
    }
}

# 10. FINALIZATION
# --------------------------------------------------------
Write-Host "`n [5/6] Refreshing Network Stack..." -ForegroundColor Magenta
Restart-Service -Name Spooler -Force
ipconfig /flushdns | Out-Null
nbtstat -R | Out-Null
Write-Log "ACTION" "Print Spooler Restarted & DNS Flushed."

Write-Host "`n [6/6] SUCCESS! Configuration Complete." -ForegroundColor Green
Write-Host " =================================================================" -ForegroundColor Cyan

# Smart IP Display
if ($Role -ne "CLIENT") {
    Write-Host " YOUR HOST IP ADDRESS IS:" -ForegroundColor Yellow
    $IPs = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
        $_.InterfaceAlias -notmatch 'Loopback|vEthernet' -and $_.IPAddress -notmatch '169.254'
    } | Select-Object -ExpandProperty IPAddress
    Write-Host " $IPs" -ForegroundColor White
}

Write-Host " =================================================================" -ForegroundColor Cyan
Write-Host "`n [IMPORTANT] A REBOOT IS REQUIRED FOR SMB1 & SECURITY CHANGES." -ForegroundColor Red

$RebootChoice = Read-Host " Reboot now? (y/n)"
if ($RebootChoice -eq 'y') {
    Restart-Computer -Force
} else {
    Write-Host " Please reboot manually before testing." -ForegroundColor Yellow
    Pause
}
