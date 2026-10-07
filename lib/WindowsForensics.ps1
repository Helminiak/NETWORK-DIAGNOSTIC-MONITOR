# Optional Windows adapters. All slow work runs independently from scheduling/rendering.
function Test-IsAdministrator {
    try{$id=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=[Security.Principal.WindowsPrincipal]::new($id);return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}catch{return $false}
}

function Start-CorroboratedCapture {
    param($Assessment)
    if(-not $Assessment.CaptureEligible -or -not $PacketCaptureEnabled -or $script:CaptureWorker -or $Clock.ElapsedMilliseconds -lt $script:CaptureNextMs){return}
    $script:CaptureNextMs=$Clock.ElapsedMilliseconds+$Cfg.CaptureCooldownSec*1000
    $path=Join-Path $PacketDir ('PktMon_'+[guid]::NewGuid().ToString('N')+'.etl')
    if(-not (Reserve-Storage $path ($Cfg.PacketCaptureMaxMB*1MB+1MB))){Write-EventLog 'Capture skipped: insufficient quota headroom; telemetry monitoring continues.' 'STORAGE_WARNING';return}
    [void](Write-ManagedText ($path+'.capture.json') (@{SensorName=$Cfg.SENSOR_NAME;SensorRole=$Cfg.SENSOR_ROLE;RunId=$RunId;StartedUTC=[datetime]::UtcNow.ToString('o');MaxMB=$Cfg.PacketCaptureMaxMB;Seconds=$Cfg.PacketCaptureSec;Mode='circular'} | ConvertTo-Json) -Critical)
    $pool=[runspacefactory]::CreateRunspacePool(1,1);$pool.Open();$ps=[powershell]::Create();$ps.RunspacePool=$pool
    $worker=@'
param($Exe,$Path,$Seconds,$Bytes,$MaxMB,$Cancel,$Queue,$Identity)
$ErrorActionPreference='Continue';$owned=$false
function Report([string]$Type,[string]$Message){$Queue.Enqueue([pscustomobject]@{Kind='DIAGNOSTIC';Type=$Type;Message=$Message})}
function RunPktMon([string]$Arguments){
    $p=[Diagnostics.Process]::new();$p.StartInfo=[Diagnostics.ProcessStartInfo]::new($Exe,$Arguments)
    $p.StartInfo.UseShellExecute=$false;$p.StartInfo.CreateNoWindow=$true;$p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true
    try{[void]$p.Start();$o=$p.StandardOutput.ReadToEndAsync();$e=$p.StandardError.ReadToEndAsync();if(-not $p.WaitForExit(10000)){$p.Kill();[void]$p.WaitForExit(1000);return @{Code=-1;Text='PktMon command deadline exceeded.'}};$text=$o.Result+$e.Result;if($text.Length -gt 32000){$text=$text.Substring(0,32000)};return @{Code=$p.ExitCode;Text=$text}}finally{$p.Dispose()}
}
try{
    # An unsupported flag is a failure; never retry with an unbounded mode.
    $start=RunPktMon ('start --capture --pkt-size '+$Bytes+' --file-name "'+$Path+'" --file-size '+$MaxMB+' --log-mode circular')
    if($start.Code -ne 0){Report 'CAPTURE_FAILED' ('PktMon start failed (an existing capture is never stopped): '+$start.Text);return}
    $owned=$true;Report 'CAPTURE_STARTED' $Path
    $timer=[Diagnostics.Stopwatch]::StartNew()
    while(-not $Cancel.Stop -and $timer.Elapsed.TotalSeconds -lt $Seconds){Start-Sleep -Milliseconds 100}
}finally{
    if($owned){
        $stop=RunPktMon 'stop'
        [IO.File]::WriteAllText($Path+'.status.txt',$Identity+"`r`nStopExit="+$stop.Code+' MaxMB='+$MaxMB+' Seconds='+$Seconds+" Mode=circular`r`n"+$stop.Text)
        Report 'CAPTURE_FINISHED' ('StopExit='+$stop.Code+' bounded ETL retained; '+$Path)
    }
}
'@
    [void]$ps.AddScript($worker).AddArgument($PktMonExe).AddArgument($path).AddArgument($Cfg.PacketCaptureSec).AddArgument($Cfg.PacketCaptureBytes).AddArgument($Cfg.PacketCaptureMaxMB).AddArgument($script:Cancel).AddArgument($Queue).AddArgument(('Sensor='+$Cfg.SENSOR_NAME+' Role='+$Cfg.SENSOR_ROLE+' Run='+$RunId+' UTC='+[datetime]::UtcNow.ToString('o')))
    $script:CaptureWorker=[pscustomobject]@{PowerShell=$ps;Handle=$ps.BeginInvoke();Pool=$pool;Path=$path}
}

function Save-IncidentSnapshot {
    param($Assessment)
    $dir=$Recorder.Path
    [void][IO.Directory]::CreateDirectory($dir)
    $record=[ordered]@{SchemaVersion=1;TimestampUTC=[datetime]::UtcNow.ToString('o');Timestamp=[datetime]::Now.ToString('o');SensorName=$Cfg.SENSOR_NAME;SensorRole=$Cfg.SENSOR_ROLE;RunId=$RunId;EpisodeId=$State.EpisodeId;Assessment=$Assessment;LatestEvidence=@($script:Latest.Values);PacketCapture=if($script:CaptureWorker){$script:CaptureWorker.Path}else{''}}
    [void](Write-ManagedText (Join-Path $dir ('Snapshot_'+$State.EpisodeId+'.json')) ($record | ConvertTo-Json -Depth 9) -Critical)
    # Never run incident traceroutes simultaneously; request the existing trace worker.
    if($Scheduler.Jobs.TRACE.Enabled){$Scheduler.Jobs.TRACE.Requested=$true}
    $pool=[runspacefactory]::CreateRunspacePool(1,1);$pool.Open();$ps=[powershell]::Create();$ps.RunspacePool=$pool
    $worker=@'
param($Dir,$Identity)
$ErrorActionPreference='Continue'
[void][IO.Directory]::CreateDirectory($Dir)
$script:Remaining=4MB
function SaveEvidence([string]$Name,[string]$Text){
    $Text=$Identity+"`r`n"+$Text
    if($Text.Length -gt 60000){$Text=$Text.Substring(0,60000)+"`r`n[TRUNCATED: per-file evidence limit]"}
    $bytes=[Text.Encoding]::UTF8.GetByteCount($Text)+3
    if($bytes -le $script:Remaining){[IO.File]::WriteAllText((Join-Path $Dir $Name),$Text,([Text.UTF8Encoding]::new($true)));$script:Remaining-=$bytes}
}
foreach($command in @(@{Exe='ipconfig.exe';Args=@('/all');File='ipconfig_all.txt'},@{Exe='route.exe';Args=@('print');File='route_print.txt'},@{Exe='arp.exe';Args=@('-a');File='arp_a.txt'},@{Exe='netstat.exe';Args=@('-s');File='netstat_s.txt'},@{Exe='netstat.exe';Args=@('-ano');File='netstat_ano.txt'})){
    $process=[Diagnostics.Process]::new();$process.StartInfo=[Diagnostics.ProcessStartInfo]::new($command.Exe,($command.Args -join ' '))
    $process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true;$process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
    try{
        [void]$process.Start();$output=$process.StandardOutput.ReadToEndAsync();$errorText=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(3000)){$process.Kill();[void]$process.WaitForExit(1000)}
        SaveEvidence $command.File ($output.Result+$errorText.Result)
    }finally{try{if(-not $process.HasExited){$process.Kill()}}catch{};$process.Dispose()}
}
try{SaveEvidence 'Get-NetAdapter.txt' (Get-NetAdapter -ErrorAction Stop | Format-List * | Out-String -Width 240)}catch{}
try{SaveEvidence 'Get-NetAdapterStatistics.txt' (Get-NetAdapterStatistics -ErrorAction Stop | Format-List * | Out-String -Width 240)}catch{}
try{SaveEvidence 'Get-NetIPConfiguration.txt' (Get-NetIPConfiguration -Detailed -ErrorAction Stop | Format-List * | Out-String -Width 240)}catch{}
try{SaveEvidence 'Get-DnsClientServerAddress.txt' (Get-DnsClientServerAddress -ErrorAction Stop | Format-Table -AutoSize | Out-String -Width 240)}catch{}
try{SaveEvidence 'Windows_System_Network_Events.txt' (Get-WinEvent -FilterHashtable @{LogName='System';StartTime=(Get-Date).AddMinutes(-10)} -MaxEvents 100 -ErrorAction Stop | Where-Object{$_.ProviderName -match 'Tcpip|DNS|NDIS|Network|Dhcp|e2f|Netwtw'} | Format-List TimeCreated,Id,ProviderName,Message | Out-String -Width 240)}catch{}
try{SaveEvidence 'DNS_Client_Operational.txt' (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational';StartTime=(Get-Date).AddMinutes(-10)} -MaxEvents 100 -ErrorAction Stop | Format-List TimeCreated,Id,ProviderName,Message | Out-String -Width 240)}catch{}
'@
    if($script:EvidenceWorker){
        # One collector at a time; newer snapshots already contain portable evidence.
        $ps.Dispose();$pool.Close();$pool.Dispose()
    }else{
        $evidencePath=Join-Path $dir ('WindowsEvidence_'+$State.EpisodeId)
        if(-not (Reserve-Storage $evidencePath 4MB)){$ps.Dispose();$pool.Close();$pool.Dispose();Write-EventLog 'Windows collector skipped: insufficient quota headroom; portable snapshot retained.' 'STORAGE_WARNING';return $dir}
        [void]$ps.AddScript($worker).AddArgument($evidencePath).AddArgument(('Sensor='+$Cfg.SENSOR_NAME+' Role='+$Cfg.SENSOR_ROLE+' Run='+$RunId))
        $script:EvidenceWorker=[pscustomobject]@{PowerShell=$ps;Handle=$ps.BeginInvoke();Pool=$pool;StartedMs=$Clock.ElapsedMilliseconds;IncidentPath=$dir;Path=$evidencePath}
    }
    return $dir
}

function Step-ForensicsWorkers {
    foreach($name in @('CaptureWorker','EvidenceWorker')){
        $worker=Get-Variable -Name $name -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if(-not $worker){continue}
        if($name -eq 'EvidenceWorker' -and $Clock.ElapsedMilliseconds-$worker.StartedMs -gt 45000){$worker.PowerShell.Stop();Write-EventLog 'Windows evidence collection deadline reached; portable incident snapshot was saved.' 'FORENSICS_WARNING'}
        if($worker.Handle.IsCompleted){
            try{[void]$worker.PowerShell.EndInvoke($worker.Handle);if($worker.PowerShell.Streams.Error.Count){Write-EventLog ($worker.PowerShell.Streams.Error | Out-String) 'FORENSICS_WARNING'}}catch{Write-EventLog $_.Exception.Message 'FORENSICS_WARNING'}
            finally{$worker.PowerShell.Dispose();$worker.Pool.Close();$worker.Pool.Dispose();Set-Variable -Name $name -Value $null -Scope Script;Release-StorageReservation $worker.Path}
        }
    }
}

function Stop-ForensicsWorkers {
    $script:Cancel.Stop=$true
    if($script:CaptureWorker){
        # Let the worker's finally stop only the capture it successfully started.
        [void]$script:CaptureWorker.Handle.AsyncWaitHandle.WaitOne(12000)
    }
    Step-ForensicsWorkers
    if($script:EvidenceWorker){$worker=$script:EvidenceWorker;$worker.PowerShell.Stop();$worker.PowerShell.Dispose();$worker.Pool.Close();$worker.Pool.Dispose();$script:EvidenceWorker=$null;Release-StorageReservation $worker.Path}
    if($script:CaptureWorker){$worker=$script:CaptureWorker;$worker.PowerShell.Stop();$worker.PowerShell.Dispose();$worker.Pool.Close();$worker.Pool.Dispose();$script:CaptureWorker=$null;Release-StorageReservation $worker.Path}
}
