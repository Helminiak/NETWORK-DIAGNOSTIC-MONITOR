function New-ProbeScheduler {
    param($Config,[string]$ProbePath,$Context,$Queue,$Clock)
    $pool=[runspacefactory]::CreateRunspacePool(1,9);$pool.Open()
    $jobs=[ordered]@{}
    foreach($name in @('ICMP','DNS','TCP443','HTTPS','NIC','TCP_STATS','DNS_TRANSPORT','MTU','TRACE')){
        $s=$Config.Schedules[$name]
        $bound=switch($name){
            ICMP { $Context.Targets.Count*($Config.PingTimeoutMs+500+$Config.PingStaggerMs) }
            DNS { $Context.AllDnsResolvers.Count*($Config.DnsTimeoutMs+100) }
            TCP443 { $Config.TcpConnectTargets.Count*($Config.DnsTimeoutMs+$Config.TcpConnectTimeoutMs+100) }
            HTTPS { $Config.HttpsSites.Count*(($Config.HttpsTimeoutSec+2)*1000+100) }
            DNS_TRANSPORT { $Context.TransportResolvers.Count*($Config.DnsTimeoutMs*2+6500) }
            MTU { $Config.MtuTargets.Count*$Config.MtuPayloadSizes.Count*($Config.PingTimeoutMs+200) }
            TRACE { $Config.TraceTargets.Count*($Config.TraceBudgetSec*1000+1500) }
            default { 20000 }
        }
        $jobs[$name]=[pscustomobject]@{Name=$name;IntervalMs=[long]($s.IntervalSec*1000);NextMs=[long]$s.PhaseMs;Enabled=[bool]$s.Enabled;PowerShell=$null;Handle=$null;StartedMs=0L;Sequence=0L;Skipped=0L;Completed=0L;Aborted=0L;Failed=0L;LastCompletedMs=0L;DeadlineSlots=0L;ScheduledStarts=0L;RequestedStarts=0L;BudgetMs=[long]($bound+5000);Requested=$false}
    }
    return [pscustomobject]@{Pool=$pool;Jobs=$jobs;Config=$Config;ProbePath=$ProbePath;Context=$Context;Queue=$Queue;Clock=$Clock;WorkerScript=''}
}

function Step-ProbeScheduler {
    param($Scheduler)
    $now=$Scheduler.Clock.ElapsedMilliseconds
    foreach($job in $Scheduler.Jobs.Values){
        if($job.Handle -and $job.Handle.IsCompleted){
            try{
                [void]$job.PowerShell.EndInvoke($job.Handle)
                if($job.PowerShell.Streams.Error.Count -gt 0){throw ($job.PowerShell.Streams.Error | Out-String)}
                $job.Completed++;$job.LastCompletedMs=$now
            }catch{$job.Failed++;throw}finally{$job.PowerShell.Dispose();$job.PowerShell=$null;$job.Handle=$null}
        }
        if($job.Handle -and $now-$job.StartedMs -gt $job.BudgetMs){throw "Worker $($job.Name) exceeded its bounded sweep budget; monitoring stopped to avoid reporting stale data."}
        if(-not $job.Enabled -or ($now -lt $job.NextMs -and -not $job.Requested)){continue}
        $slots=if($now -ge $job.NextMs){1+[long][math]::Floor(($now-$job.NextMs)/$job.IntervalMs)}else{0}
        $job.NextMs+=$slots*$job.IntervalMs;$job.DeadlineSlots+=$slots
        # A resumed/suspended coordinator used to silently discard every elapsed
        # deadline except the last one when the family was idle (Skipped=0).
        # Count those missed slots explicitly; never attempt catch-up bursts.
        if($job.Handle){$job.Skipped+=$slots;continue}
        if($slots -gt 1){$job.Skipped+=($slots-1)}
        if($slots -gt 0){$job.ScheduledStarts++}else{$job.RequestedStarts++}
        $job.Requested=$false;$job.Sequence++
        $ps=[powershell]::Create();$ps.RunspacePool=$Scheduler.Pool
        $worker=@'
param($ProbePath,$Cfg,$Ctx,$Queue,$Clock,$Family,$SweepId,$QueryName)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
. $ProbePath
Invoke-ProbeFamily
'@
        if($Scheduler.WorkerScript){$worker=$Scheduler.WorkerScript}
        [void]$ps.AddScript($worker).AddArgument($Scheduler.ProbePath).AddArgument($Scheduler.Config).AddArgument($Scheduler.Context).AddArgument($Scheduler.Queue).AddArgument($Scheduler.Clock).AddArgument($job.Name).AddArgument(($job.Name+':'+$job.Sequence)).AddArgument($Scheduler.Config.DnsNames[($job.Sequence-1)%$Scheduler.Config.DnsNames.Count])
        $job.PowerShell=$ps;$job.StartedMs=$now;$job.Handle=$ps.BeginInvoke()
    }
}

function Stop-ProbeScheduler {
    param($Scheduler)
    if(-not $Scheduler){return}
    foreach($job in $Scheduler.Jobs.Values){
        if($job.PowerShell){
            try{
                if($job.Handle.IsCompleted){[void]$job.PowerShell.EndInvoke($job.Handle);if($job.PowerShell.Streams.Error.Count){throw 'Probe worker ended with errors during shutdown.'};$job.Completed++;$job.LastCompletedMs=$Scheduler.Clock.ElapsedMilliseconds}
                else{$job.PowerShell.Stop();$job.Aborted++}
            }catch{$job.Failed++}finally{$job.PowerShell.Dispose();$job.PowerShell=$null;$job.Handle=$null}
        }
    }
    $Scheduler.Pool.Close();$Scheduler.Pool.Dispose()
}
