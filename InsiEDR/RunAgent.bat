@echo off
TITLE InsiEDR Continuous Monitoring Agent
COLOR 0A

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
echo          InsiEDR Telemetry Monitoring Agent
echo =======================================================
echo.
echo [INFO] Initializing environment...

:: Navigate to the project directory
cd /d "%~dp0"

:: Verify virtual environment exists
if not exist ".venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found at .venv\Scripts\activate.bat
    echo Please ensure the project is set up correctly.
    pause
    exit /b 1
)

:: Activate the virtual environment
echo [INFO] Activating virtual environment...
call ".venv\Scripts\activate.bat"

:: Run the agent
echo [INFO] Starting agent in continuous BACKGROUND mode...
echo [INFO] You can safely close this terminal. The agent will run silently!
echo.

:: We are already elevated, so we can tell the agent to skip its internal UAC prompt
set INSIEDR_SCHEDULED_TASK=1
set PYTHONUNBUFFERED=1

:: Start the agent securely in the background using Agent_Windows.exe (no console window)
start "" ".venv\Scripts\Agent_Windows.exe" -u -m agent.agent

:: Automatically exit to close the terminal while the agent persists
exit
