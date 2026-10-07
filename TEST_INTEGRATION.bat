@echo off
setlocal
cd /d "%~dp0"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Integration_Test.ps1"
set "RESULT=%ERRORLEVEL%"
echo Integration exit code: %RESULT%
pause
exit /b %RESULT%
