#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$RunPath,[Parameter(Mandatory=$true)][string]$OutputDir,[switch]$AssertOctoberFixture)
$ErrorActionPreference='Stop'
foreach($lib in @('Time','AddressPolicy','Core','Diagnostics','Resources','Runtime','WebStatus')){. (Join-Path $PSScriptRoot ('lib/'+$lib+'.ps1'))}
$script:Cfg=Read-MonitorConfig (Join-Path $PSScriptRoot 'Monitor_Config.psd1')
$original=Get-Content -Raw -LiteralPath (Join-Path $RunPath 'Configuration.json') | ConvertFrom-Json
$Cfg.SENSOR_NAME=$original.SensorName;$Cfg.SENSOR_ROLE=$original.SensorRole
$script:RouteInfo=$original.SelectedRoute
$script:Latest=@{};$script:State=New-IncidentState;$script:RecentHistory=New-Object Collections.ArrayList
$script:TrafficHistory=New-Object Collections.ArrayList;$script:NicCurrent=$null;$script:IncidentCount=0
$script:Continuity=[pscustomobject]@{GapCount=$null;BlindMs=$null};$script:Storage=[pscustomobject]@{Dropped=$null};$script:DeploymentStatus='HISTORICAL_REPLAY';$script:PowerGuard='HISTORICAL';$script:RingExpired=$null;$script:RingCapacityEvicted=$null
$script:Scheduler=[pscustomobject]@{Jobs=@{}};$script:Targets=@([pscustomobject]@{Name='Default-Gateway';IP=$RouteInfo.Gateway;Role='Gateway'})
$raw=@(Get-ChildItem -LiteralPath (Join-Path $RunPath 'Incidents') -Directory | ForEach-Object{foreach($file in @('PreEvent.csv','Event.csv','PostEvent.csv')){$p=Join-Path $_.FullName $file;if(Test-Path -LiteralPath $p){Import-Csv -LiteralPath $p}}})
$seen=@{};$rows=@($raw | Where-Object{if($seen.ContainsKey($_.EvidenceId)){$false}else{$seen[$_.EvidenceId]=$true;$true}} | Sort-Object {[long]$_.EndMonoMs})
if($rows.Count -eq 0){throw 'No canonical incident CSV rows; healthy observations that were never persisted cannot be replayed.'}
$summaryPath=Join-Path $RunPath 'Summary_Final.txt'
if(Test-Path -LiteralPath $summaryPath){
    $summary=Get-Content -Raw -LiteralPath $summaryPath
    if($summary -match 'detected gaps=(\d+)'){$Continuity.GapCount=[int]$Matches[1]}
    if($summary -match 'coordinator gap time=\s*([0-9.]+)s'){$Continuity.BlindMs=[long]([double]$Matches[1]*1000)}
    if($summary -match 'suppressed writes=(\d+)'){$Storage.Dropped=[int]$Matches[1]}
}
$timeline=New-Object Collections.ArrayList;$last='';$recoveries=0;$privateRows=0;$privateAddresses=@{}
foreach($row in $rows){
    $row.StartMonoMs=[long]$row.StartMonoMs;$row.EndMonoMs=[long]$row.EndMonoMs
    if($row.LatencyMs -ne ''){$row.LatencyMs=[double]$row.LatencyMs}else{$row.LatencyMs=$null}
    $data=$row.DataJSON | ConvertFrom-Json;$row | Add-Member NoteProperty Data $data
    if(Test-ObservationAnswerAnomaly $row $Cfg){if($row.Protocol -eq 'DNS_UDP'){$privateRows++};foreach($ip in $data.Addresses){$privateAddresses[$ip]=$true}}
    $key=$row.Family+':'+$row.Protocol+':'+$row.Name
    if($row.Protocol -in @('DNS_UDP','DNS_TCP')){$key+=':'+$data.QueryName}
    if($row.Protocol -eq 'NIC' -and $row.Status -eq 'OK'){
        $rate=Get-InterfaceTrafficDelta $data $script:NicCurrent $row.EndMonoMs $script:NicMonoMs 30
        $data | Add-Member NoteProperty RxMbps $rate.RxMbps -Force;$data | Add-Member NoteProperty TxMbps $rate.TxMbps -Force;$data | Add-Member NoteProperty CounterState $rate.CounterState -Force
        $script:NicCurrent=$data;$script:NicMonoMs=$row.EndMonoMs
        [void]$script:TrafficHistory.Add([pscustomobject]@{monoMs=$row.EndMonoMs;rxMbps=$rate.RxMbps;txMbps=$rate.TxMbps})
        while($script:TrafficHistory.Count -gt 120){$script:TrafficHistory.RemoveAt(0)}
    }
    $Latest[$key]=$row
    $script:Clock=[pscustomobject]@{ElapsedMilliseconds=$row.EndMonoMs}
    $script:Assessment=Get-CoreAssessment @($Latest.Values) $row.EndMonoMs $Cfg
    $actions=@(Update-IncidentState $State $Assessment @($Latest.Values) $row.EndMonoMs $Cfg)
    if($actions -contains 'INCIDENT'){$script:IncidentCount++}
    if($actions -contains 'RECOVERY'){$recoveries++}
    if($last -ne $Assessment.Code -or $actions.Count){[void]$timeline.Add([pscustomobject]@{utc=$row.TimestampUTC;monoMs=$row.EndMonoMs;code=$Assessment.Code;active=$State.Active;actions=$actions});$last=$Assessment.Code}
}
[void][IO.Directory]::CreateDirectory($OutputDir)
$script:LastErrorState=if($State.Active){'ACTIVE'}elseif($recoveries){'RECOVERED'}else{'CLEAR'}
$snapshot=New-WebStatusSnapshot 'HISTORICAL'
$snapshot.generatedUtc=$rows[-1].TimestampUTC
$snapshot.network.unresolvedAtStop=([bool]$State.Active -and (Test-Path -LiteralPath (Join-Path $RunPath 'Run_Closed.json')))
$snapshot.monitor.probes='HISTORICAL_REPLAY'
[IO.File]::WriteAllText((Join-Path $OutputDir 'historical-status.json'),($snapshot | ConvertTo-Json -Depth 12),([Text.UTF8Encoding]::new($false)))
[IO.File]::WriteAllText((Join-Path $OutputDir 'replay-timeline.json'),(@($timeline) | ConvertTo-Json -Depth 8),([Text.UTF8Encoding]::new($false)))
$result=[pscustomobject]@{uniqueRows=$rows.Count;nonpublicDnsUdpRows=$privateRows;returnedNonpublicAddresses=@($privateAddresses.Keys);confirmedEpisodes=$IncidentCount;finalCode=$Assessment.Code;active=$State.Active;recovered=([bool]$recoveries -and -not $State.Active);scope='Incident archive only; not a replay of the entire run'}
$result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDir 'replay-result.json') -Encoding UTF8
if($AssertOctoberFixture -and ($privateRows -ne 1033 -or $State.Active -ne 'DNS_ANSWER_REDIRECTION' -or @($timeline | Where-Object{$_.actions -contains 'INCIDENT' -and $_.code -eq 'UPSTREAM_WAN_CONFIRMED'}).Count)){throw 'Historical replay regression: expected 1033 private UDP answers, DNS redirection unresolved, zero confirmed WAN episodes.'}
Write-Host ('PASS Historical replay: '+$rows.Count+' unique observations; '+$privateRows+' private UDP answers; active='+$State.Active+'.')
