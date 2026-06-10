@echo off
title Aegis-Tunnel X Launcher
cd /d "%~dp0"

echo.
echo   ======================================
echo        AEGIS-TUNNEL X  LAUNCHER
echo   ======================================
echo.

echo [1/3] Starting Dashboard...
start "Aegis Dashboard" "C:\Users\graph\AppData\Local\Programs\Python\Python311\python.exe" dashboard\app.py
timeout /t 2 /nobreak >nul

echo [2/3] Starting Server...
start "Aegis Server" "C:\Users\graph\AppData\Local\Programs\Python\Python311\python.exe" server.py
timeout /t 2 /nobreak >nul

echo [3/3] Starting Client...
start "Aegis Client" "C:\Users\graph\AppData\Local\Programs\Python\Python311\python.exe" client.py

echo.
echo   All components running!
echo   Dashboard : http://127.0.0.1:5000
echo.
echo   Press any key to stop everything...
echo.
pause >nul

echo Shutting down...
taskkill /fi "WINDOWTITLE eq Aegis Dashboard" /f >nul 2>&1
taskkill /fi "WINDOWTITLE eq Aegis Server" /f >nul 2>&1
taskkill /fi "WINDOWTITLE eq Aegis Client" /f >nul 2>&1
echo Done.
