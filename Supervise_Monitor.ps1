#Requires -Version 5.1
[CmdletBinding()]
param([string]$ConfigPath='',[int]$DurationSec=0)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'lib/Runtime.ps1')
. (Join-Path $PSScriptRoot 'lib/Deployment.ps1')
$child=$null;$lock=$null;$control=$null;$runDir='';$childStart='';$failure=0
try{
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'Supervisor deployment requires Windows PowerShell 5.1.'}
    if($PSVersionTable.PSVersion.Major -ne 5){throw 'Use Windows PowerShell 5.1 for unattended deployment.'}
    if(-not $ConfigPath){$ConfigPath=Join-Path $PSScriptRoot 'Monitor_Config.psd1'}
    $ConfigPath=[IO.Path]::GetFullPath($ConfigPath);$cfg=Read-MonitorConfig $ConfigPath
    $cfg.RootDir=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($cfg.RootDir)
    $control=Join-Path $cfg.RootDir ('Supervisor_'+$cfg.SENSOR_NAME)
    [void][IO.Directory]::CreateDirectory($control)
    if(([IO.File]::GetAttributes($control) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Supervisor control directory cannot be a reparse point.'}
    $lock=[IO.File]::Open((Join-Path $control '.supervisor.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    foreach($old in Get-ChildItem -LiteralPath $control -File -Filter 'Heartbeat_*.json'){
        if($old.BaseName -notmatch '^Heartbeat_[0-9a-f]{32}$'){continue}
        try{$saved=[IO.File]::ReadAllText($old.FullName) | ConvertFrom-Json;if(-not (Test-ProcessIdentity $saved.ProcessId $saved.ProcessStartedUTC)){[IO.File]::Delete($old.FullName)}}catch{}
    }
    $engine=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $monitor=Join-Path $PSScriptRoot 'Network_Diagnostic_V2_12_RC3.ps1'
    $parentStart=Get-ProcessStartIdentity $PID
    $clock=[Diagnostics.Stopwatch]::StartNew();$nextLaunch=0L;$progress=$null;$token='';$heartbeatPath='';$lastHeartbeat=$null
    Write-SupervisorLog $control ('START account='+[Security.Principal.WindowsIdentity]::GetCurrent().Name+' parent='+$PID)
    while($DurationSec -le 0 -or $clock.Elapsed.TotalSeconds -lt $DurationSec){
        if([IO.File]::Exists((Join-Path $control 'StopSupervisor.txt'))){break}
        $now=$clock.ElapsedMilliseconds
        if(-not $child -and $now -ge $nextLaunch){
            $token=[guid]::NewGuid().ToString('N');$heartbeatPath=Join-Path $control ('Heartbeat_'+$token+'.json')
            $command='& '+"'"+$monitor.Replace("'","''")+"'"+' -NoDashboard -Quiet -ConfigPath '+"'"+$ConfigPath.Replace("'","''")+"'"+' -ControlPath '+"'"+$heartbeatPath.Replace("'","''")+"'"+' -SupervisorToken '+"'"+$token+"'"+' -SupervisorPid '+$PID+' -SupervisorStartedUTC '+"'"+$parentStart+"'"
            $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
            $start=[Diagnostics.ProcessStartInfo]::new($engine,('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+$encoded))
            $start.UseShellExecute=$false;$start.CreateNoWindow=$true
            $child=[Diagnostics.Process]::new();$child.StartInfo=$start
            [void]$child.Start();$childStart=Get-ProcessStartIdentity $child.Id
            $progress=New-SupervisorProgress $now;$runDir='';$lastHeartbeat=$null
            Write-SupervisorLog $control ('CHILD_START pid='+$child.Id+' token='+$token)
        }
        if($child){
            $heartbeat=$null
            try{if([IO.File]::Exists($heartbeatPath)){$heartbeat=[IO.File]::ReadAllText($heartbeatPath) | ConvertFrom-Json}}catch{}
            $decision=Update-SupervisorProgress $progress $heartbeat $token $child.Id $childStart $now 120000 90000
            if($decision.Valid){$runDir=$heartbeat.RunDir;$lastHeartbeat=$heartbeat}
            if($decision.SupervisorGap){Write-SupervisorLog $control 'SUPERVISOR_GAP missed polling; reset stall grace. Network state unknown during interruption.'}
            if($child.HasExited -or $decision.Restart){
                $reason=if($child.HasExited){'EXIT='+$child.ExitCode}else{'STALE_CONTROL_HEARTBEAT'}
                Write-SupervisorLog $control ('CHILD_RESTART '+$reason)
                Stop-OwnedMonitor $child $childStart $runDir
                $child.Dispose();$child=$null
                if([IO.File]::Exists($heartbeatPath)){[IO.File]::Delete($heartbeatPath)}
                $nextLaunch=$now+30000 # bounded restart rate; no rapid failure loops
            }
        }
        Start-Sleep -Milliseconds 1000
    }
}catch{
    $failure=1
    if($control -and $lock){try{Write-SupervisorLog $control ('FATAL '+$_.Exception.Message)}catch{}}
    [Console]::Error.WriteLine($_.Exception.Message)
}finally{
    if($child){try{Stop-OwnedMonitor $child $childStart $runDir}catch{$failure=1;[Console]::Error.WriteLine($_.Exception.Message)};$ownedExited=$child.HasExited;$child.Dispose()}
    if($heartbeatPath -and [IO.File]::Exists($heartbeatPath) -and (-not $child -or $ownedExited)){try{[IO.File]::Delete($heartbeatPath)}catch{}}
    if($lock){try{Write-SupervisorLog $control 'STOP'}catch{$failure=1};$lock.Dispose()}
}
exit $failure
