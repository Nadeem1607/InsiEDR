@echo off
:: ============================================================
:: InsiEDR Agent - Persistent Launcher
:: Auto-elevates to Admin, installs config & binary to ProgramData,
:: registers as a Scheduled Task to survive reboots, and starts agent.
:: ============================================================

:: Check if already running as Admin
net session >nul 2>&1
if %errorLevel% == 0 goto :run

:: Not Admin - re-launch this script as Admin (UAC prompt)
echo [InsiEDR] Requesting Administrator privileges...
powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
if %errorLevel% neq 0 (
    echo [ERROR] Administrative privileges are required to install the endpoint agent!
    echo Please run the script again and click "Yes" when prompted by User Account Control.
    pause
)
exit /b

:run
echo [InsiEDR] Running as Administrator. Setting up persistence...

:: Create ProgramData directory if missing
if not exist "C:\ProgramData\InsiEDR" mkdir "C:\ProgramData\InsiEDR"
if not exist "C:\ProgramData\InsiEDR\logs" mkdir "C:\ProgramData\InsiEDR\logs"

:: Copy the environment config and the executable to the system path
echo [InsiEDR] Copying configuration and executable...
copy /Y "%~dp0.env" "C:\ProgramData\InsiEDR\.env" >nul
copy /Y "%~dp0insidedr_agent.exe" "C:\ProgramData\InsiEDR\insidedr_agent.exe" >nul

:: Kill any old running instance (if it was running manually)
taskkill /f /im insidedr_agent.exe >nul 2>&1
timeout /t 2 /nobreak >nul

:: Register the scheduled task to start the agent silently on boot as SYSTEM
echo [InsiEDR] Registering persistent scheduled task...
schtasks /create /f /tn "InsiEDR_Agent" /tr "C:\ProgramData\InsiEDR\insidedr_agent.exe" /sc ONLOGON /rl HIGHEST >nul
if %errorLevel% neq 0 (
    echo [ERROR] Failed to register the scheduled task!
    pause
    exit /b
)

:: Start the agent via the scheduled task
echo [InsiEDR] Starting agent silently in the background...
schtasks /run /tn "InsiEDR_Agent" >nul
if %errorLevel% neq 0 (
    echo [ERROR] Failed to start the agent!
    pause
    exit /b
)

echo [SUCCESS] InsiEDR Agent has been installed and started successfully!
echo The agent will automatically run in the background upon reboot.
echo Logs are available at: C:\ProgramData\InsiEDR\logs\agent.log
timeout /t 5 /nobreak >nul
