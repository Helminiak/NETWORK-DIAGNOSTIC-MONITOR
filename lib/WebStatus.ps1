# Local read-only transport. Dedicated C# thread never invokes PowerShell or disk IO.
function Start-WebStatus {
    param($Config,[string]$AssetRoot)
    if(-not $Config.EnableWebStatus){return $null}
    if(-not ('NetDiagStatusServer' -as [type])){
        Add-Type -Path (Join-Path $PSScriptRoot 'WebStatusServer.cs')
    }
    $server=New-Object NetDiagStatusServer
    foreach($asset in @('index.html','app.js','style.css')){
        $server.AddAsset('/'+$asset,[IO.File]::ReadAllBytes((Join-Path $AssetRoot $asset)))
    }
    $server.Start([int]$Config.WebStatusPort)
    return $server
}

function New-WebStatusSnapshot {
    param([string]$Lifecycle='RUNNING')
    $now=[long]$Clock.ElapsedMilliseconds
    $health=Get-MonitorHealth $Assessment $State $Scheduler $now $Cfg
    $probes=@(foreach($row in $script:Latest.Values | Sort-Object EndMonoMs -Descending | Select-Object -First 256){
        $age=[math]::Max(0,$now-$row.EndMonoMs)
        $policy=if($row.Protocol -in @('DNS_UDP','DNS_TCP')){Get-DnsAnswerPolicy $row.Data.QueryName $row.Data.Addresses $Cfg}elseif(Test-ObservationAnswerAnomaly $row $Cfg){'PUBLIC_NAME_NONPUBLIC_ANSWER'}else{''}
        [pscustomobject][ordered]@{id=$row.EvidenceId;family=$row.Family;protocol=$row.Protocol;name=$row.Name;provider=$row.Provider;scope=$row.Scope;status=if($age -gt $Cfg.EvidenceWindowSec*1000){'STALE'}else{$row.Status};wireStatus=$row.Status;stage=$row.Stage;latencyMs=$row.LatencyMs;ageMs=$age;ip=$row.Data.IP;queryName=$row.Data.QueryName;addresses=@($row.Data.Addresses | Where-Object{$_});answerPolicy=$policy;resolutionMode=$row.Data.ResolutionMode;publicDestination=([bool]$row.Data.IP -and (Test-PublicProbeAddress $row.Data.IP));signature=$row.Data.Signature;dnsTransport=$row.Data.DnsTransport;dnsFallbackReason=$row.Data.DnsFallbackReason;httpMethod=$row.Data.HttpMethod;measurement=$row.Data.Measurement}
    })
    $nodes=New-Object Collections.ArrayList
    [void]$nodes.Add([pscustomobject]@{id='sensor';label=$Cfg.SENSOR_NAME;kind='sensor';address='';status=if($Lifecycle -eq 'RUNNING'){$health.Probes}else{'STOPPED'};basis='Sensor process and scheduled probes'})
    foreach($target in $Targets | Where-Object{$_.Role -in @('Gateway','Gateway2','LAN')}){
        $last=$probes | Where-Object{$_.protocol -eq 'ICMP' -and $_.name -eq $target.Name} | Sort-Object ageMs | Select-Object -First 1
        [void]$nodes.Add([pscustomobject]@{id=$target.Name;label=$target.Name;kind=$target.Role;address=$target.IP;status=if($last){$last.status}else{'UNMEASURED'};basis='ICMP reachability from this sensor; forwarding health unproven'})
    }
    $publicReplies=@($probes | Where-Object{$_.protocol -eq 'TCP443' -and $_.resolutionMode -eq 'PINNED_IP' -and $_.publicDestination -and $_.status -eq 'OK'})
    [void]$nodes.Add([pscustomobject]@{id='upstream';label='Internet path';kind='upstream';address='';status=if($Assessment.Code -eq 'UPSTREAM_WAN_CONFIRMED'){'FAIL'}elseif($publicReplies.Count -ge 2){'OK'}else{'UNDETERMINED'};basis='Single-sensor path; router and ISP ownership unproven'})
    $dnsAnomalies=@($probes | Where-Object{$_.answerPolicy -eq 'PUBLIC_NAME_NONPUBLIC_ANSWER' -and $_.status -ne 'STALE'})
    $sensorLink=$script:NicCurrent
    [pscustomobject][ordered]@{
        schemaVersion=1;programVersion='V2.12-RC3.1.1';generatedUtc=[datetime]::UtcNow.ToString('o');monoMs=$now;lifecycle=$Lifecycle
        sensor=[pscustomobject]@{name=$Cfg.SENSOR_NAME;role=$Cfg.SENSOR_ROLE;adapter=$RouteInfo.AdapterName;linkSpeed=(Get-CurrentLinkSpeed);gateway=$RouteInfo.Gateway;systemDns=$RouteInfo.SystemDns;deployment=$script:DeploymentStatus}
        network=[pscustomobject]@{code=$Assessment.Code;severity=$Assessment.Severity;text=$Assessment.Text;activeIncident=$State.Active;incidentCount=$IncidentCount;scope='SENSOR_PATH';recovered=($script:LastErrorState -eq 'RECOVERED' -and -not $State.Active -and -not $Assessment.IncidentEligible);unresolvedAtStop=($Lifecycle -ne 'RUNNING' -and [bool]$State.Active);answerAnomalyCount=$dnsAnomalies.Count;returnedAddresses=@($dnsAnomalies.addresses | Sort-Object -Unique)}
        monitor=[pscustomobject]@{probes=$health.Probes;powerGuard=$script:PowerGuard;gapCount=$Continuity.GapCount;blindMs=$Continuity.BlindMs;storageDropped=$Storage.Dropped;ringExpired=$script:RingExpired;ringCapacityEvicted=$script:RingCapacityEvicted;webStatus='LOCAL_READ_ONLY';resources=(Get-ProcessResourceSnapshot $Lifecycle);advisories=@(Get-AdvisorySummary);failureStages=@(Get-FailureStageSummary);failureStageOmitted=$script:FailureStageOmitted;advisoryKeysOmitted=$script:AdvisoryKeysOmitted;dnsFallbacks=@(Get-DnsFallbackSummary);dnsFallbackOmitted=$script:DnsFallbackOmitted}
        topology=[pscustomobject]@{nodes=@($nodes);edges=@(foreach($n in $nodes | Where-Object{$_.kind -in @('Gateway','Gateway2','LAN')}){[pscustomobject]@{from='sensor';to=$n.id;basis='OBSERVED_ICMP_PATH'}})+@([pscustomobject]@{from='Default-Gateway';to='upstream';basis='CONFIGURED_UPSTREAM_PATH_UNPROVEN'});inventoryComplete=$false;lanClientCount=$null;routerWanMeasured=$false}
        traffic=[pscustomobject]@{scope='SENSOR_INTERFACE';rxMbps=$sensorLink.RxMbps;txMbps=$sensorLink.TxMbps;counterState=$sensorLink.CounterState;routerWanRxMbps=$null;routerWanTxMbps=$null;history=@($script:TrafficHistory)}
        probeRowsOmitted=[math]::Max(0,$script:Latest.Count-256);probes=$probes
        scheduler=@(foreach($job in $Scheduler.Jobs.Values){[pscustomobject]@{family=$job.Name;enabled=$job.Enabled;started=$job.Sequence;completed=$job.Completed;skipped=$job.Skipped;failed=$job.Failed;inFlight=[bool]$job.Handle}})
        recentEvents=@($script:RecentHistory)
        limitations=@('This sensor does not discover the entire LAN. Add verified LanTargets to measure known devices.','Link speed is a PHY rate. Traffic counters describe the selected sensor interface, not whole-home WAN use.','DNS public-address policy does not verify DNSSEC or prove resolver identity.','DOH_ENDPOINT measures endpoint reachability only.','Topology edges are configured/probed paths, not a physical cable inventory.')
    }
}

function Publish-WebStatus {
    param([string]$Lifecycle='RUNNING')
    if(-not $script:WebServer){return}
    $snapshot=New-WebStatusSnapshot $Lifecycle
    $json=$snapshot | ConvertTo-Json -Depth 10 -Compress
    $script:WebServer.Publish($json)
    if($Lifecycle -ne 'RUNNING' -and $RunDir){[void](Write-ManagedText (Join-Path $RunDir 'Status_Final.json') $json -Critical -Final)}
}
