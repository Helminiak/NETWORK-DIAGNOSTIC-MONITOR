# Power and process/control adapters. Control metadata never contains probe rows.
function Start-IdleSleepGuard {
    param([bool]$Enabled)
    if(-not $Enabled){return 'DISABLED'}
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){return 'UNSUPPORTED_PLATFORM'}
    if(-not ('NetDiagPower' -as [type])){
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class NetDiagPower {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint SetThreadExecutionState(uint flags);
    public static bool Start() { return SetThreadExecutionState(0x80000001u) != 0; }
    public static void Stop() { SetThreadExecutionState(0x80000000u); }
}
'@
    }
    if(-not [NetDiagPower]::Start()){throw 'Windows rejected the idle-sleep prevention request.'}
    return 'ACTIVE'
}
function Stop-IdleSleepGuard {
    if('NetDiagPower' -as [type]){[NetDiagPower]::Stop()}
}
function Get-ProcessStartIdentity {
    param([int]$ProcessId=$PID)
    $process=[Diagnostics.Process]::GetProcessById($ProcessId)
    try{return $process.StartTime.ToUniversalTime().ToString('o')}finally{$process.Dispose()}
}
function Test-ProcessIdentity {
    param([int]$ProcessId,[string]$StartedUTC)
    try{return (Get-ProcessStartIdentity $ProcessId) -eq $StartedUTC}catch{return $false}
}
function Write-ControlHeartbeat {
    param([string]$Path,[string]$Token,[string]$StartedUTC)
    if(-not $Path){return}
    $health=Get-MonitorHealth $Assessment $State $Scheduler $Clock.ElapsedMilliseconds $Cfg
    $record=@{SchemaVersion=1;Token=$Token;ProcessId=$PID;ProcessStartedUTC=$StartedUTC;RunId=$RunId;RunDir=$RunDir;TimestampUTC=[datetime]::UtcNow.ToString('o');MonoMs=$Clock.ElapsedMilliseconds;Network=$health.Network;Probes=$health.Probes;Power=$script:PowerGuard;Status='RUNNING'}
    Write-AtomicText $Path ($record | ConvertTo-Json -Compress)
}
function New-SupervisorProgress {
    param([long]$NowMs)
    [pscustomobject]@{LastProgressMs=$NowMs;LastTickMs=$NowMs;ChildMonoMs=-1L;HasHeartbeat=$false;RestartCount=0L}
}
function Update-SupervisorProgress {
    param($Progress,$Heartbeat,[string]$Token,[int]$ChildId,[string]$ChildStartedUTC,[long]$NowMs,[long]$StartupMs,[long]$StaleMs)
    # A gap in this independent process is also blind time, never a WAN outage.
    $pause=$NowMs-$Progress.LastTickMs -gt 15000
    $Progress.LastTickMs=$NowMs
    if($pause){$Progress.LastProgressMs=$NowMs}
    $valid=$Heartbeat -and $Heartbeat.Token -eq $Token -and $Heartbeat.ProcessId -eq $ChildId -and $Heartbeat.ProcessStartedUTC -eq $ChildStartedUTC -and $Heartbeat.Status -eq 'RUNNING'
    if($valid -and [long]$Heartbeat.MonoMs -gt $Progress.ChildMonoMs){
        $Progress.ChildMonoMs=[long]$Heartbeat.MonoMs;$Progress.LastProgressMs=$NowMs;$Progress.HasHeartbeat=$true
    }
    $limit=if($Progress.HasHeartbeat){$StaleMs}else{$StartupMs}
    [pscustomobject]@{Restart=($NowMs-$Progress.LastProgressMs -gt $limit);SupervisorGap=$pause;Valid=[bool]$valid}
}
function Write-SupervisorLog {
    param([string]$Directory,[string]$Message)
    $path=Join-Path $Directory 'Supervisor.log'
    if([IO.File]::Exists($path) -and (Get-Item -LiteralPath $path).Length -ge 1MB){
        $old=$path+'.previous';if([IO.File]::Exists($old)){[IO.File]::Delete($old)};[IO.File]::Move($path,$old)
    }
    [IO.File]::AppendAllText($path,([datetime]::UtcNow.ToString('o')+' '+$Message+"`r`n"))
}
function Stop-OwnedMonitor {
    param($Child,[string]$StartedUTC,[string]$RunDir,[int]$GraceSec=20)
    if(-not $Child -or $Child.HasExited){return}
    # Never stop a process from a stale PID file: only this directly launched child
    # and its independently recorded start identity are eligible.
    if(-not (Test-ProcessIdentity $Child.Id $StartedUTC)){throw 'Owned child identity no longer matches; refusing process termination.'}
    if($RunDir -and [IO.Directory]::Exists($RunDir)){
        [IO.File]::WriteAllText((Join-Path $RunDir 'Stop.txt'),'Supervisor requested graceful shutdown.')
        if($Child.WaitForExit($GraceSec*1000)){return}
    }
    if(-not (Test-ProcessIdentity $Child.Id $StartedUTC)){throw 'Child identity changed during graceful shutdown.'}
    $Child.Kill()
    if(-not $Child.WaitForExit(10000)){throw 'Owned child did not exit; refusing a replacement writer.'}
}
