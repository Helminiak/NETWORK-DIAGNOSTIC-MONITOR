#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$ConfigPath='',[string]$TaskName='NetDiag-V2.12-RC3',[System.Management.Automation.PSCredential]$Credential,[switch]$StartNow)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion.Major -ne 5){throw 'Use Windows PowerShell 5.1.'}
if(-not $ConfigPath){$ConfigPath=Join-Path $PSScriptRoot 'Monitor_Config.psd1'}
. (Join-Path $PSScriptRoot 'lib/Runtime.ps1')
$ConfigPath=[IO.Path]::GetFullPath($ConfigPath);$cfg=Read-MonitorConfig $ConfigPath
if(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue){throw 'Task already exists; export/review it before replacing. Installer will not overwrite an existing task.'}
if(-not $Credential){$Credential=Get-Credential -UserName ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -Message 'Windows account password for startup before login; use the same account as Pushover setup. PIN is not an account password.'}
if(-not $Credential){throw 'A Windows account credential is required.'}
$exe=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$scriptPath=Join-Path $PSScriptRoot 'Supervise_Monitor.ps1'
if($scriptPath -match '["\r\n]' -or $ConfigPath -match '["\r\n]'){throw 'Invalid script/config path.'}
$action=New-ScheduledTaskAction -Execute $exe -Argument ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$scriptPath+'" -ConfigPath "'+$ConfigPath+'"') -WorkingDirectory $PSScriptRoot
$trigger=New-ScheduledTaskTrigger -AtStartup
$settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
# Password logon permits pre-login execution and the same account's encrypted secrets.
# S4U is deliberately not used. No password is written into source, logs or exports.
$principal=New-ScheduledTaskPrincipal -UserId $Credential.UserName -LogonType Password -RunLevel Highest
$task=New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description ('Network monitor supervisor for sensor '+$cfg.SENSOR_NAME+'. Candidate; Windows acceptance required.')
$password=$Credential.GetNetworkCredential().Password
try{[void](Register-ScheduledTask -TaskName $TaskName -InputObject $task -User $Credential.UserName -Password $password)}finally{$password=$null;$Credential=$null}
Write-Host ('Registered '+$TaskName+'. Use StopSupervisor.txt for graceful shutdown before disabling/removing the task. Complete PRODUCTION_ACCEPTANCE.md.')
if($StartNow){Start-ScheduledTask -TaskName $TaskName}
