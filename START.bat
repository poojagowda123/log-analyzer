@echo off
REM LogAnalyzer Pro - Quick Start Batch Script
REM Run this as Administrator for full functionality

echo.
echo ========================================
echo  LOG ANALYZER PRO - STARTUP
echo ========================================
echo.

REM Check if running as admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo WARNING: Not running as Administrator!
    echo Some features will be limited.
    echo Please run this script as Administrator.
    echo.
    pause
)

REM Navigate to project root
cd /d "%~dp0"

echo [1/4] Installing Python dependencies...
python -m pip install --upgrade pip -q
pip install -r requirements.txt -q

if %errorlevel% neq 0 (
    echo ERROR: Failed to install dependencies!
    pause
    exit /b 1
)

echo.
echo [2/4] Generating demo data...
python src/generate_demo_data.py

if %errorlevel% neq 0 (
    echo ERROR: Failed to generate demo data!
    pause
    exit /b 1
)

echo.
echo [3/4] Verifying output folder...
if not exist "Output\ml_anomalies.csv" (
    echo ERROR: Demo data not created!
    pause
    exit /b 1
)

echo.
echo ========================================
echo  STARTUP COMPLETE!
echo ========================================
echo.
echo Choose an option:
echo.
echo   [1] Start Dashboard Only (Quick)
echo   [2] Start Security Daemon (Advanced)
echo   [3] Run Both (Recommended)
echo   [4] Exit
echo.
set /p choice="Enter your choice (1-4): "

if "%choice%"=="1" (
    echo Starting Dashboard...
    streamlit run dashboard/app.py
) else if "%choice%"=="2" (
    echo Starting Security Daemon...
    cd src
    python main_security_daemon.py --interval 60 --dry-run
    cd ..
) else if "%choice%"=="3" (
    echo.
    echo Starting Dashboard in new window...
    start "LogAnalyzer Dashboard" cmd /k "cd /d "%CD%" && streamlit run dashboard/app.py"
    echo.
    echo Starting Security Daemon in new window...
    start "LogAnalyzer Daemon" cmd /k "cd /d "%CD%\src" && python main_security_daemon.py --interval 60 --dry-run"
    echo.
    echo Both services started. Press Enter to close this window...
    pause
) else (
    echo Exiting...
    exit /b 0
)
