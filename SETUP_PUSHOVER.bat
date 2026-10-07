@echo off
setlocal
cd /d "%~dp0"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Configure_Pushover.ps1"
set "RESULT=%ERRORLEVEL%"
pause
exit /b %RESULT%
