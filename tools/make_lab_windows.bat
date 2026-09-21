@echo off
setlocal
cd /d "%~dp0\.."

echo ============================================================
echo DLS21 Preservation Project - v8.13 LAB / USER-CA Builder
echo ============================================================
echo.

if "%~1"=="" (
    echo Usage:
    echo   tools\make_lab_windows.bat "C:\path\to\DLS21_813.apk"
    echo.
    pause
    exit /b 2
)

py tools\make_lab.py "%~1"
set ERR=%ERRORLEVEL%

echo.
if "%ERR%"=="0" (
    echo SUCCESS.
) else (
    echo Builder returned code %ERR%.
)

pause
exit /b %ERR%
