@echo off
rem Starts the vulnerable shop (5000) and the detector dashboard (8000) in two windows.
cd /d "%~dp0"
start "ShopSecure (victim)" cmd /k python -m victim_site.app
start "Sentinel (detector)" cmd /k python -m detector.main
timeout /t 3 >nul
start http://127.0.0.1:8000
start http://127.0.0.1:5000
