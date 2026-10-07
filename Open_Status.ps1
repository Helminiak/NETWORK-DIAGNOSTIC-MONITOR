#Requires -Version 5.1
param([string]$ConfigPath='')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'lib/Runtime.ps1')
if(-not $ConfigPath){$ConfigPath=Join-Path $PSScriptRoot 'Monitor_Config.psd1'}
$cfg=Read-MonitorConfig $ConfigPath
if(-not $cfg.EnableWebStatus){throw 'EnableWebStatus is false.'}
Start-Process -FilePath ('http://127.0.0.1:'+$cfg.WebStatusPort+'/')
