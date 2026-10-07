#Requires -Version 5.1
param([string]$ConfigPath='')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'lib/Runtime.ps1')
if(-not $ConfigPath){$ConfigPath=Join-Path $PSScriptRoot 'Monitor_Config.psd1'}
$cfg=Read-MonitorConfig $ConfigPath
$control=Join-Path $cfg.RootDir ('Supervisor_'+$cfg.SENSOR_NAME)
if(-not [IO.Directory]::Exists($control)){throw 'No supervisor control directory exists for this sensor.'}
if(([IO.File]::GetAttributes($control) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Unsafe control path.'}
[IO.File]::WriteAllText((Join-Path $control 'StopSupervisor.txt'),'Requested UTC='+[datetime]::UtcNow.ToString('o'))
Write-Host 'Graceful background shutdown requested. START_BACKGROUND clears this stop marker on the next manual launch.'
