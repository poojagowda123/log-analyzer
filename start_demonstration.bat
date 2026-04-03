@echo off
echo ===================================================
echo   LOG ANALYZER PRO - DEMO MODE LAUNCHER
echo ===================================================

echo [1/2] Generating Fresh Demo Anomalies...
python src/generate_demo_data.py

echo.
echo [2/2] Launching Dashboard...
echo (Please refresh the browser page if it is already open)
streamlit run dashboard/app.py

pause
