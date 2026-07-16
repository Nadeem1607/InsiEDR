@echo off
TITLE Stop InsiEDR Agent
COLOR 0C

:: Check for Administrative Privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :isAdmin
) else (
    echo [INFO] Requesting Administrative Privileges...
    powershell -Command "Start-Process -FilePath '%~dpnx0' -Verb RunAs"
    exit /b
)

:isAdmin
echo =======================================================
echo          Stopping InsiEDR Telemetry Agent
echo =======================================================
echo.
echo [INFO] Sending shutdown signal to Agent_Windows.exe...
echo [INFO] The agent will intercept this, fire its tamper payload to the SIEM, and safely exit.
echo.

:: Create a stop signal file for the agent to detect in the default state directory
echo STOP > "%PROGRAMDATA%\InsiEDR\stop.signal"

:: Give the agent 3 seconds to process the signal and fire the tamper payload
timeout /t 3 /nobreak >nul

:: Forcefully terminate the agent to ensure it is completely stopped
taskkill /F /IM Agent_Windows.exe >nul 2>&1

:: Clean up the signal file
if exist "%PROGRAMDATA%\InsiEDR\stop.signal" del "%PROGRAMDATA%\InsiEDR\stop.signal"

echo.
echo [SUCCESS] Shutdown signal sent successfully.
echo.
pause
