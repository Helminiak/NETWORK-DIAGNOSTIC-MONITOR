@echo off
setlocal
cd /d "%~dp0"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Network_Diagnostic_V2_12_RC3.ps1" -SelfTest
set "RESULT=%ERRORLEVEL%"
echo Self-test exit code: %RESULT%
pause
exit /b %RESULT%
