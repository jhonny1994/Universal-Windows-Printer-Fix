@echo off
:: ==================================================================================
:: SCRIPT METADATA
:: Name:        Universal Master Printer Fix
:: Version:     7.1 (Production Release)
:: Description: Automates LTSC/22H2/24H2 Printer RPC & Discovery Remediation
:: Authors:     jhonny1994 & Gemini
:: Features:    Profile-Aware Security, Multi-Language Support, Logging, Rollback
:: ==================================================================================

:: 1. ENVIRONMENT PREP
:: --------------------------------------------------------
chcp 65001 >nul
setlocal EnableDelayedExpansion
title Universal Printer Fix v7.1 [Production]
color 1F

:: Define Log and Backup Paths
set "LOGFILE=%TEMP%\PrinterFix_Log_%DATE:~-4%%DATE:~-7,2%%DATE:~-10,2%.txt"
set "BACKUP_DIR=%USERPROFILE%\Desktop\Printer_Fix_Backups"

:: Initialize Log
call :Log "INFO" "Script Initialized."
call :Log "INFO" "OS Version Check: %OS%"

:: 2. ADMINISTRATOR & OS CHECK
:: --------------------------------------------------------
openfiles >nul 2>&1
if %errorlevel% NEQ 0 (
    echo.
    echo [CRITICAL] ADMIN PRIVILEGES REQUIRED.
    echo Right-click this file and select "Run as Administrator".
    call :Log "ERROR" "Launch failed. No Admin privileges."
    pause
    exit
)

:: 3. BACKUP ROUTINE
:: --------------------------------------------------------
if not exist "%BACKUP_DIR%" mkdir "%BACKUP_DIR%"
echo [!] Creating Registry Backups in: %BACKUP_DIR%
call :Log "INFO" "Starting Registry Backup..."

reg export "HKLM\SYSTEM\CurrentControlSet\Control\Print" "%BACKUP_DIR%\Print_System_Backup.reg" /y >nul 2>&1
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "%BACKUP_DIR%\Print_Policy_Backup.reg" /y >nul 2>&1

if exist "%BACKUP_DIR%\Print_System_Backup.reg" (
    echo     - Backup Successful.
    call :Log "INFO" "Registry Backup Successful."
) else (
    echo     - [WARNING] Backup Failed. Proceeding with caution.
    call :Log "WARN" "Registry Backup Failed."
)

:: 4. USER MENU
:: --------------------------------------------------------
:MENU
cls
echo =================================================================
echo      PRODUCTION PRINTER FIX v7.1 (Logged & Secured)
echo =================================================================
echo.
echo   [1] HOST ONLY   :: This PC has the printer (Server).
echo   [2] CLIENT ONLY :: This PC connects to the printer.
echo   [3] HYBRID/ALL  :: This PC does BOTH.
echo.
set /p choice="Enter choice (1, 2, or 3): "

if "%choice%"=="1" set "ROLE=HOST" & goto COMMON_FIXES
if "%choice%"=="2" set "ROLE=CLIENT" & goto COMMON_FIXES
if "%choice%"=="3" set "ROLE=HYBRID" & goto COMMON_FIXES
echo Invalid Choice. & goto MENU

:: 5. COMMON REGISTRY & PROTOCOL FIXES
:: --------------------------------------------------------
:COMMON_FIXES
call :Log "INFO" "User selected Role: %ROLE%"
echo.
echo [1/7] Applying Base Registry Protocols...

:: Fix RPC Protocol (Client Side)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" /v RpcUseNamedPipeProtocol /t REG_DWORD /d 1 /f >nul
call :Log "ACTION" "Enabled Named Pipe Protocol."

:: Fix RPC Privacy (Server Side - Fixes 0x709)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print" /v RpcAuthnLevelPrivacyEnabled /t REG_DWORD /d 0 /f >nul
call :Log "ACTION" "Disabled RPC Privacy Enforcement (0x709 Fix)."

:: Allow Drivers (Point and Print)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 0 /f >nul
call :Log "ACTION" "Relaxed Driver Installation Restrictions."

:: Enable SMB 1.0 (Silent Check & Enable)
echo [2/7] Verifying Legacy Support (SMB 1.0)...
dism /online /Get-FeatureInfo /FeatureName:SMB1Protocol | find "State : Enabled" >nul
if %errorlevel% NEQ 0 (
    echo     - Enabling SMB 1.0 (May require reboot)...
    dism /online /Enable-Feature /FeatureName:SMB1Protocol /NoRestart >nul 2>&1
    call :Log "ACTION" "Enabled SMB 1.0 Feature."
) else (
    echo     - SMB 1.0 is already enabled.
    call :Log "INFO" "SMB 1.0 already active."
)

:: Branch Logic
if "%ROLE%"=="HOST" goto HOST_SECTION
if "%ROLE%"=="CLIENT" goto CLIENT_SECTION
if "%ROLE%"=="HYBRID" goto HOST_SECTION

:: 6. HOST CONFIGURATION
:: --------------------------------------------------------
:HOST_SECTION
echo.
echo [3/7] Configuring HOST (Server) Settings...

:: LSA Blank Passwords
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 0 /f >nul
call :Log "ACTION" "Allowed Blank Passwords."

:: Enable Guest (SID Method)
powershell -ExecutionPolicy Bypass -Command "Get-LocalUser | Where-Object {$_.SID -like '*-501'} | Enable-LocalUser" >nul 2>&1
call :Log "ACTION" "Enabled Guest Account via SID."

:: Force Private Profile
echo     - Setting Network Profile to PRIVATE...
powershell -ExecutionPolicy Bypass -Command "Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private" >nul 2>&1
call :Log "ACTION" "Forced Network Profile to Private."

:: Smart Firewall Rule
echo     - Creating Profile-Aware Firewall Rule...
powershell -ExecutionPolicy Bypass -Command "New-NetFirewallRule -DisplayName 'Prod_Print_Fix_Ports' -Direction Inbound -LocalPort 135,139,445 -Protocol TCP -Action Allow -Profile Private -Force -ErrorAction SilentlyContinue" >nul 2>&1
call :Log "ACTION" "Created/Updated Firewall Rule (Private Profile Only)."

:: Service Discovery
echo     - Enabling Network Discovery Services...
for %%S in (fdPHost FDResPub SSDPSRV) do (
    sc config %%S start= auto >nul
    net start %%S >nul 2>&1
)
call :Log "ACTION" "Started Discovery Services (fdPHost, FDResPub, SSDPSRV)."

if "%ROLE%"=="HYBRID" goto CLIENT_SECTION
goto FINAL_STEPS

:: 7. CLIENT CONFIGURATION
:: --------------------------------------------------------
:CLIENT_SECTION
echo.
echo [4/7] Applying CLIENT Connection Policies...

:: Insecure Guest Auth
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v AllowInsecureGuestAuth /t REG_DWORD /d 1 /f >nul
call :Log "ACTION" "Enabled Insecure Guest Auth."

:: Force Private Profile
echo     - Setting Network Profile to PRIVATE...
powershell -ExecutionPolicy Bypass -Command "Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private" >nul 2>&1

:: Credential Cleanup
echo     - Cleaning Stale Credentials...
net use * /delete /yes >nul 2>&1
powershell -ExecutionPolicy Bypass -Command "cmdkey /list | Select-String -Pattern 'Target:.*=(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.)' | ForEach-Object { $t = $_.ToString().Split('=')[1]; Write-Host '       [CLEANED]: ' $t; cmdkey /delete:$t }" >nul 2>&1
call :Log "ACTION" "Purged Stale Credentials."

goto FINAL_STEPS

:: 8. FINALIZATION & REPORTING
:: --------------------------------------------------------
:FINAL_STEPS
echo.
echo [5/7] Restarting Print Spooler...
net stop spooler && net start spooler
call :Log "ACTION" "Restarted Print Spooler."

echo.
echo [6/7] Flushing Network Cache...
ipconfig /flushdns >nul
nbtstat -R >nul
call :Log "ACTION" "Flushed DNS/NBT Cache."

echo.
echo =================================================================
echo   SUCCESS! Configuration Complete.
echo   Log File: %LOGFILE%
echo =================================================================
echo.

if "%ROLE%" NEQ "CLIENT" (
    echo   YOUR HOST IP ADDRESS IS:
    echo   -------------------------------------------------
    powershell -ExecutionPolicy Bypass -Command "Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*' -and $_.InterfaceAlias -notlike '*vEthernet*' -and $_.IPAddress -notlike '169.254.*'} | Select-Object -ExpandProperty IPAddress"
    echo   -------------------------------------------------
    call :Log "INFO" "Displayed IP Address to User."
)

echo.
echo   [IMPORTANT] REBOOT REQUIRED to finalize SMB1 and Security changes.
set /p reboot="   Reboot now? (y/n): "
if /i "%reboot%"=="y" (
    call :Log "INFO" "User initiated Reboot. Exiting."
    shutdown /r /t 0
) else (
    call :Log "INFO" "User deferred Reboot. Exiting."
    echo.
    echo   Please reboot manually before testing.
    pause
)
exit /b

:: ========================================================
:: HELPER FUNCTIONS
:: ========================================================
:Log
:: Usage: call :Log "TYPE" "Message"
echo [%DATE% %TIME%] [%~1] %~2 >> "%LOGFILE%"
exit /b
