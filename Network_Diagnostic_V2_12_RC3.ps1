#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ConfigPath='',
    [switch]$SelfTest,
    [switch]$Diagnostic,
    [int]$DurationSec=0,
    [switch]$NoDashboard,
    [switch]$Quiet,
    [string]$ControlPath='',
    [string]$SupervisorToken='',
    [int]$SupervisorPid=0,
    [string]$SupervisorStartedUTC='',
    [string]$LogRoot=''
)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$script:RunDir=$null;$script:Writers=@{};$script:Scheduler=$null;$script:Cfg=$null
$script:CaptureWorker=$null;$script:EvidenceWorker=$null;$script:Cancel=[hashtable]::Synchronized(@{Stop=$false})
$script:FatalErrorMessage=$null;$script:CaptureNextMs=0L;$script:FailureExit=0
$script:Storage=$null;$script:StorageLock=$null;$script:LogPaths=@{};$script:Recorder=$null
$script:Alerts=$null;$script:WebServer=$null
try{
    if(-not $ConfigPath){$ConfigPath=Join-Path $PSScriptRoot 'Monitor_Config.psd1'}
    foreach($library in @('Time','AddressPolicy','Core','Diagnostics','Resources','WebStatus','Scheduler','Continuity','Runtime','Storage','Notifications','Presentation','WindowsForensics','Deployment')){. (Join-Path $PSScriptRoot ('lib\'+$library+'.ps1'))}
    if($SelfTest){. (Join-Path $PSScriptRoot 'lib\SelfTest.ps1');Invoke-MonitorSelfTest;exit 0}
    $script:Cfg=Read-MonitorConfig $ConfigPath
    if($LogRoot){$Cfg.RootDir=$LogRoot}
    $Cfg.RootDir=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Cfg.RootDir)
    if($Diagnostic){$Cfg.EnablePacketCapture=$false;$Cfg.EnablePushover=$false;if($DurationSec -le 0){$DurationSec=60}}
    if($DurationSec -lt 0){throw 'DurationSec cannot be negative.'}
    Initialize-Notifications
    $script:PowerGuard=Start-IdleSleepGuard $Cfg.PreventIdleSleep
    $script:ProcessStartedUTC=Get-ProcessStartIdentity $PID
    $script:DeploymentStatus=if($SupervisorPid){'SUPERVISED_CANDIDATE'}else{'MANUAL_CANDIDATE'}
    if($SupervisorPid -and (-not $ControlPath -or $SupervisorToken -notmatch '^[0-9a-f]{32}$' -or -not (Test-ProcessIdentity $SupervisorPid $SupervisorStartedUTC))){throw 'Invalid supervisor ownership/control arguments.'}
    $script:RunId=[guid]::NewGuid().ToString('N')
    Initialize-Storage
    Connect-NotificationStorage
    $script:RunDir=Join-Path $SensorRoot ('Run_'+[datetime]::Now.ToString('yyyyMMdd_HHmmss')+'_'+$Cfg.SENSOR_NAME+'_'+$RunId.Substring(0,8))
    foreach($folder in @('','Routes','Incidents','PacketCaptures')){[void][IO.Directory]::CreateDirectory((Join-Path $RunDir $folder))}
    $script:RouteDir=Join-Path $RunDir 'Routes';$script:IncidentRoot=Join-Path $RunDir 'Incidents';$script:PacketDir=Join-Path $RunDir 'PacketCaptures'
    $script:StartTime=[datetime]::Now;$script:Clock=[Diagnostics.Stopwatch]::StartNew()
    Open-RunLogs
    $ctx=Get-SensorContext $Cfg
    $script:RouteInfo=$ctx.RouteInfo;$script:Targets=$ctx.Targets;$script:AllDnsResolvers=$ctx.AllDnsResolvers
    $script:HttpsSites=$Cfg.HttpsSites;$script:TcpConnectTargets=$Cfg.TcpConnectTargets;$script:DnsTransportResolvers=$ctx.TransportResolvers
    $script:TopologyMode=switch($Cfg.SENSOR_ROLE){DIRECT_BGW{'DIRECT_BGW'}BEHIND_ASUS{'ROUTER_BEHIND_BGW'}default{'GENERIC_ROUTER'}}
    $script:SystemDnsRole=$ctx.SystemDnsRole;$script:BgwManagementIP=$Cfg.BgwManagementIP;$script:BgwTarget=$Targets | Where-Object{$_.IP -eq $BgwManagementIP} | Select-Object -First 1
    $script:CurlExe=$ctx.CurlExe;$script:IsAdministrator=Test-IsAdministrator
    $script:PktMonExe=(Get-Command pktmon.exe -ErrorAction SilentlyContinue).Source
    $script:PacketCaptureEnabled=[bool]($Cfg.EnablePacketCapture -and $IsAdministrator -and $PktMonExe)
    Initialize-DisplayState
    $script:Queue=[Collections.Concurrent.ConcurrentQueue[object]]::new()
    $script:State=New-IncidentState;$script:Assessment=New-Assessment 'WAITING_FOR_EVIDENCE' 'WATCH' 'Probe families are starting at independent phase offsets.'
    $script:LastDnsName='-'
    [void](Write-ManagedText (Join-Path $RunDir 'Configuration.json') (@{SchemaVersion=1;StorageSchemaVersion=1;SensorName=$Cfg.SENSOR_NAME;SensorRole=$Cfg.SENSOR_ROLE;RunId=$RunId;TimestampUTC=[datetime]::UtcNow.ToString('o');Config=$Cfg;SelectedRoute=$RouteInfo;TimeZone=[TimeZoneInfo]::Local.Id} | ConvertTo-Json -Depth 7) -Critical)
    # START schedules only after initialization; phase deadlines are relative to this epoch.
    $script:Scheduler=New-ProbeScheduler $Cfg (Join-Path $PSScriptRoot 'lib\Probes.ps1') $ctx $Queue $Clock
    if(-not $NoDashboard){
        $Host.UI.RawUI.WindowTitle='Network Diagnostic Monitor V2.12-RC3.1 - '+$Cfg.SENSOR_NAME+' ['+$Cfg.SENSOR_ROLE+']'
        Set-ConsolePresentation
        try{[Console]::CursorVisible=$false;[Console]::TreatControlCAsInput=$true}catch{}
    }
    # Console setup may take a second; start the phase epoch only when ready.
    $Clock.Restart()
    $script:Continuity=New-ContinuityState 0 ([datetime]::UtcNow)
    Write-EventLog ('V2.12-RC3.1 started. SensorRole='+$Cfg.SENSOR_ROLE+'; Adapter='+$RouteInfo.AdapterName+'; Gateway='+$RouteInfo.Gateway+'; SystemDNS='+$RouteInfo.SystemDns) 'START'
    if($Cfg.SENSOR_ROLE -eq 'GENERIC' -and $Cfg.EnableBgwProbe){Write-EventLog 'CONFIGURATION: Generic sensor role intentionally disables explicit BGW management probes; configure role to BEHIND_ASUS only after verifying topology.' 'CONFIG_WARNING'}
    if($Alerts.Mode -in @('NOT_CONFIGURED','CONFIG_ERROR','STATE_ERROR')){Write-EventLog ('Pushover '+$Alerts.Mode+'. Run SETUP_PUSHOVER.bat under the same Windows account; monitoring continues.') 'NOTIFICATION_SETUP'}
    if($Cfg.EnableWebStatus){
        try{$script:WebServer=Start-WebStatus $Cfg (Join-Path $PSScriptRoot 'web');Publish-WebStatus;Write-EventLog ('Read-only network status: http://127.0.0.1:'+$Cfg.WebStatusPort+'/') 'WEB_STATUS'}catch{Write-EventLog ('Status page unavailable: '+$_.Exception.Message+'; monitoring continues.') 'WEB_STATUS_WARNING'}
    }
    Write-RunSummary
    if($Cfg.PersistPeriodicHealthCsv){Write-HealthySummary}
    $script:LastAdvisoryLogAt=@{}
    $nextResources=0L;$nextControl=0L;$nextParent=0L;$nextWeb=0L;$webFaultReported=$false
    if($PowerGuard -ne 'ACTIVE'){Write-EventLog ('Idle-sleep prevention: '+$PowerGuard) 'DEPLOYMENT_WARNING'}
    $nextHeartbeat=[long]($Cfg.HeartbeatIntervalSec*1000)
    $nextHealth=[long]($Cfg.HealthySummaryIntervalSec*1000);$nextSummary=[long]($Cfg.SummaryIntervalSec*1000);$nextDashboard=0L;$nextStatus=0L;$nextDecision=0L;$lastAssessment=$Assessment.Code
    while(-not $script:Cancel.Stop){
        # Inspect coordinator cadence BEFORE any scheduler deadlines are skipped.
        $loopNow=$Clock.ElapsedMilliseconds
        $gap=Update-ContinuityState $Continuity $loopNow ([datetime]::UtcNow) ([long]($Cfg.CoordinatorGapThresholdSec*1000))
        if($gap){
            Reset-InFlightBudgetAfterGap $Scheduler $loopNow
            Write-EventLog ('No coordinator iterations for '+$gap.ElapsedMs+' ms; wall elapsed '+$gap.WallMs+' ms; skipped probes will be counted. This is SENSOR downtime, NOT evidence of a network outage.') 'SENSOR_GAP'
            # Never carry an unconfirmed fault candidate across an unobserved interval.
            # Leave a confirmed incident open until fresh recovery evidence exists.
            Reset-IncidentAfterGap $State
            Update-ProcessResources -Reset;$nextResources=$loopNow+30000
            $Cfg.EvidenceEpochMs=$loopNow
            $nextHeartbeat=$loopNow
            $nextSummary=0L # force an atomic updated summary after missed deadlines are counted
        }
        if($loopNow -ge $nextResources){Update-ProcessResources;$nextResources=$loopNow+30000}
        Step-ProbeScheduler $Scheduler
        $item=$null;$drained=0
        while($drained -lt 500 -and $Queue.TryDequeue([ref]$item)){
            if($item.PSObject.Properties['Kind'] -and $item.Kind -eq 'DIAGNOSTIC'){Write-EventLog $item.Message $item.Type}else{Receive-Observation $item};$item=$null;$drained++
        }
        Step-ForensicsWorkers
        $now=$Clock.ElapsedMilliseconds
        $previousActive=$State.Active
        $actions=@()
        if($now -ge $nextDecision){
            $script:Assessment=Get-CoreAssessment @($script:Latest.Values) $now $Cfg
            $actions=@(Update-IncidentState $State $Assessment @($script:Latest.Values) $now $Cfg)
            # Evaluate hold/freshness deadlines at 4 Hz; scheduling and log draining
            # remain responsive at 25 ms without repeatedly sorting identical evidence.
            $nextDecision=$now+250
        }
        foreach($action in $actions){
            switch($action){
                PRETRIGGER {Write-EventLog ($Assessment.Code+': '+$Assessment.Text) 'PRETRIGGER' $Assessment;Start-CorroboratedCapture $Assessment}
                RECLASSIFY {Write-EventLog ('Previous='+$previousActive+'; New='+$Assessment.Code) 'RECLASSIFY' $Assessment}
                INCIDENT {
                    $script:IncidentCount++;$script:LastErrorTime=[datetime]::Now;$script:LastErrorText=$Assessment.Code+' - '+$Assessment.Text;$script:LastErrorState='ACTIVE'
                    [void](Start-IncidentRecorder $Assessment)
                    Write-EventLog ($Assessment.Code+': '+$Assessment.Text) 'INCIDENT' $Assessment
                    $incident=Save-IncidentSnapshot $Assessment;Write-EventLog ('Snapshot: '+$incident) 'EVIDENCE'
                }
                RECOVERY {$script:LastErrorState='RECOVERED';Set-IncidentRecovery;Write-EventLog ('Recovered from '+$previousActive+' after fresh successful evidence and recovery hold.') 'RECOVERY' $Assessment}
            }
        }
        $script:ActiveEventCode=$State.Active
        $changed=$Assessment.Code -ne $lastAssessment
        if($changed){
            $advisory=($Assessment.Severity -eq 'WATCH' -and $Assessment.Code -notin @('WAITING_FOR_EVIDENCE','HEALTHY'))
            $firstOrDue=($advisory -and (-not $script:LastAdvisoryLogAt.ContainsKey($Assessment.Code) -or $now-$script:LastAdvisoryLogAt[$Assessment.Code] -ge $Cfg.AdvisoryLogCooldownSec*1000))
            if($Cfg.LogAdvisoryAssessmentChanges -or $State.Active -or $Assessment.Severity -in @('CRITICAL','WARNING') -or $firstOrDue){
                Write-EventLog ($lastAssessment+' -> '+$Assessment.Code+': '+$Assessment.Text) 'ASSESSMENT_CHANGE' $Assessment
                if($advisory){$script:LastAdvisoryLogAt[$Assessment.Code]=$now}
            }
            $lastAssessment=$Assessment.Code
        }
        Step-Storage
        Step-Notifications
        if($actions.Count -gt 0 -or $changed -or $now -ge $nextSummary){
            if($State.Active -or $Assessment.Severity -in @('CRITICAL','WARNING')){Write-RunSummary;$nextSummary=$now+$Cfg.SummaryIntervalSec*1000}
            elseif($now -ge $nextSummary){Write-RunSummary;$nextSummary=$now+$Cfg.IdleSummaryIntervalSec*1000}
        }
        if($now -ge $nextHeartbeat){
            $icmp=$Scheduler.Jobs['ICMP'];$dnsJob=$Scheduler.Jobs['DNS']
            Write-EventLog ('Active coordinator heartbeat; ICMP Started='+$icmp.Sequence+' Completed='+$icmp.Completed+' Skipped='+$icmp.Skipped+'; DNS Started='+$dnsJob.Sequence+' Completed='+$dnsJob.Completed+' Skipped='+$dnsJob.Skipped+'; Gaps='+$Continuity.GapCount+' BlindMs='+$Continuity.BlindMs+'; Assessment='+$Assessment.Code) 'HEARTBEAT' -Details @{Resources=(Get-ProcessResourceSnapshot);Advisories=@(Get-AdvisorySummary);FailureStages=@(Get-FailureStageSummary);DnsFallbacks=@(Get-DnsFallbackSummary);FailureStageOmitted=$script:FailureStageOmitted;AdvisoryKeysOmitted=$script:AdvisoryKeysOmitted;DnsFallbackOmitted=$script:DnsFallbackOmitted}
            $nextHeartbeat=$now+$Cfg.HeartbeatIntervalSec*1000
        }
        if($now -ge $nextHealth){
            if($Cfg.PersistPeriodicHealthCsv -or $State.Active){
                Write-HealthySummary
                foreach($job in $Scheduler.Jobs.Values){Write-CsvRecord 'Scheduler.csv' ([pscustomobject][ordered]@{TimestampUTC=[datetime]::UtcNow.ToString('o');Timestamp=[datetime]::Now.ToString('o');SensorName=$Cfg.SENSOR_NAME;SensorRole=$Cfg.SENSOR_ROLE;RunId=$RunId;Family=$job.Name;MonoMs=$now;PhaseMs=$Cfg.Schedules[$job.Name].PhaseMs;IntervalMs=$job.IntervalMs;Started=$job.Sequence;Completed=$job.Completed;Skipped=$job.Skipped;InFlight=[bool]$job.Handle})}
            }
            $nextHealth=$now+$Cfg.HealthySummaryIntervalSec*1000
        }
        if($now -ge $nextDashboard){
            $watch=@(Get-NetworkWatchItems);Update-WatchHistory $watch
            if(-not $NoDashboard){Render-Dashboard $Assessment $StartTime $LastDnsName $watch @(Get-ForensicsStatus)}
            $nextDashboard=$now+$Cfg.DashboardIntervalMs
        }
        if($script:WebServer -and $now -ge $nextWeb){
            if(-not $script:WebServer.IsAlive -and -not $webFaultReported){Write-EventLog ('Web status worker stopped: '+$script:WebServer.Error) 'WEB_STATUS_WARNING';$webFaultReported=$true}
            try{Publish-WebStatus}catch{if(-not $webFaultReported){Write-EventLog ('Status publish failed: '+$_.Exception.Message) 'WEB_STATUS_WARNING';$webFaultReported=$true}}
            $nextWeb=$now+$Cfg.WebStatusRefreshSec*1000
        }
        if($ControlPath -and $now -ge $nextControl){Write-ControlHeartbeat $ControlPath $SupervisorToken $script:ProcessStartedUTC;$nextControl=$now+30000}
        if($SupervisorPid -and $now -ge $nextParent){
            if(-not (Test-ProcessIdentity $SupervisorPid $SupervisorStartedUTC)){Write-EventLog 'Supervisor process disappeared; closing this child before a replacement owns storage.' 'SUPERVISOR_LOST';$script:Cancel.Stop=$true}
            $nextParent=$now+5000
        }
        if($NoDashboard -and -not $Quiet -and $now -ge $nextStatus){Write-Host ('Sensor={0} Role={1} Elapsed={2:N0}s Assessment={3} Active={4} Run={5}' -f $Cfg.SENSOR_NAME,$Cfg.SENSOR_ROLE,($now/1000),$Assessment.Code,$State.Active,$RunDir);$nextStatus=$now+15000}
        try{
            if(-not [Console]::IsInputRedirected -and [Console]::KeyAvailable){$key=[Console]::ReadKey($true);if($key.Key -eq 'Q' -or ($key.Key -eq 'C' -and ($key.Modifiers -band [ConsoleModifiers]::Control))){$script:Cancel.Stop=$true}}
        }catch{}
        # Stop.txt is also useful for unattended launches / controlled testing.
        if(($DurationSec -gt 0 -and $now -ge $DurationSec*1000) -or (Test-Path -LiteralPath (Join-Path $RunDir 'Stop.txt'))){$script:Cancel.Stop=$true}
        Start-Sleep -Milliseconds 25
    }
}catch{
    $script:FailureExit=1;$script:FatalErrorMessage=$_.Exception.Message
    $fatalPath=if($RunDir){Join-Path $RunDir 'Fatal_Error.log'}else{Join-Path $PSScriptRoot 'Fatal_Error.log'}
    $fatalText='NETWORK DIAGNOSTIC MONITOR V2.12-RC3.1 - FATAL ERROR'+"`r`n"+'UTC='+[datetime]::UtcNow.ToString('o')+' Local='+[datetime]::Now.ToString('o')+' Sensor='+$(if($Cfg){$Cfg.SENSOR_NAME}else{$env:COMPUTERNAME})+' Role='+$(if($Cfg){$Cfg.SENSOR_ROLE}else{'CONFIG_NOT_LOADED'})+"`r`n"+($_ | Format-List * -Force | Out-String)+"`r`n"+$_.ScriptStackTrace
    if($fatalText.Length -gt 20000){$fatalText=$fatalText.Substring(0,20000)+"`r`n[Fatal details truncated at storage safety limit]"}
    try{if($Storage -and $RunDir){if(-not (Write-ManagedText $fatalPath $fatalText -Critical -Final)){throw 'Fatal log quota exhausted.'}}else{[IO.File]::WriteAllText($fatalPath,$fatalText,([Text.UTF8Encoding]::new($true)))}}catch{[Console]::Error.WriteLine('Fatal log write also failed: '+$_.Exception.Message)}
    try{if($Writers.Count){Write-EventLog $script:FatalErrorMessage 'FATAL'}else{Receive-NotificationEvent 'FATAL' $script:FatalErrorMessage}}catch{}
    try{[Console]::CursorVisible=$true;[Console]::SetCursorPosition(0,0)}catch{}
    Write-Host '';Write-Host 'MONITOR STOPPED DUE TO A FATAL ERROR' -ForegroundColor Red
    Write-Host $script:FatalErrorMessage -ForegroundColor Red;Write-Host ('Fatal error log: '+$fatalPath) -ForegroundColor Yellow
}finally{
    if(-not $SelfTest){
        try{Stop-IdleSleepGuard}catch{$script:FailureExit=1}
        try{Stop-ProbeScheduler $Scheduler}catch{Write-Host ('Worker shutdown error: '+$_.Exception.Message) -ForegroundColor Red}
        try{Stop-ForensicsWorkers}catch{Write-Host ('Forensics shutdown error: '+$_.Exception.Message) -ForegroundColor Red}
        try{
            if($Queue){$item=$null;while($Queue.TryDequeue([ref]$item)){if($item.PSObject.Properties['Kind']){Write-EventLog $item.Message $item.Type}else{Receive-Observation $item};$item=$null}}
            if($RunDir -and $script:State){Write-EventLog ('Stopped; fatal='+[bool]$script:FatalErrorMessage) 'STOP';Close-IncidentRecorder $(if($FatalErrorMessage){'FATAL_SHUTDOWN'}else{'GRACEFUL_SHUTDOWN'});if($Cfg.PersistPeriodicHealthCsv -or $State.Active){Write-HealthySummary}}
        }catch{
            $script:FailureExit=1;Write-Host ('Final summary/log write failed: '+$_.Exception.Message) -ForegroundColor Red
            try{$detail="`r`nFinalization error: "+($_ | Out-String);if($detail.Length -gt 20000){$detail=$detail.Substring(0,20000)};$path=Join-Path $RunDir 'Fatal_Error.log';$old=if([IO.File]::Exists($path)){[IO.File]::ReadAllText($path)}else{''};[void](Write-ManagedText $path ($old+$detail) -Critical -Final)}catch{}
        }
        try{Stop-Notifications}catch{Write-Host 'Pushover shutdown failed; inspect saved alert outbox.' -ForegroundColor Yellow}
        try{if($RunDir -and $script:State){Update-ProcessResources;Write-RunSummary;Write-RunSummary 'FINAL'}}catch{
            $script:FailureExit=1;Write-Host ('Final summary write failed: '+$_.Exception.Message) -ForegroundColor Red
            try{$detail="`r`nFinalization error: "+($_ | Out-String);if($detail.Length -gt 20000){$detail=$detail.Substring(0,20000)};$path=Join-Path $RunDir 'Fatal_Error.log';$old=if([IO.File]::Exists($path)){[IO.File]::ReadAllText($path)}else{''};[void](Write-ManagedText $path ($old+$detail) -Critical -Final)}catch{}
        }
        try{if($script:WebServer){Publish-WebStatus 'STOPPED';$script:WebServer.Dispose()}}catch{$script:FailureExit=1}
        try{Stop-Storage}catch{$script:FailureExit=1;Write-Host ('Storage shutdown failed: '+$_.Exception.Message) -ForegroundColor Red}
        foreach($writer in $Writers.Values){try{$writer.Dispose()}catch{}}
        if($StorageLock){$StorageLock.Dispose()}
        try{[Console]::CursorVisible=$true;[Console]::TreatControlCAsInput=$false}catch{}
        if($RunDir){Write-Host ('Run saved: '+$RunDir)}
    }
}
exit $script:FailureExit
