function Read-MonitorConfig {
    param([string]$Path)
    $cfg=Import-PowerShellDataFile -LiteralPath $Path -ErrorAction Stop
    if(-not $cfg.SENSOR_NAME){$cfg.SENSOR_NAME=$env:COMPUTERNAME}
    if($cfg.SENSOR_NAME -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$'){throw 'SENSOR_NAME must be 1..64 letters, digits, dots, underscores or hyphens.'}
    foreach($key in @('EnableRouterDnsProbe','EnableBgwDnsProbe','PreventIdleSleep')){if($cfg[$key] -isnot [bool]){throw ($key+' must be boolean.')}}
    # Defaults allow an existing RC2 configuration to be carried forward.
    foreach($pair in @(@('EnableWebStatus',$true),@('WebStatusPort',8765),@('WebStatusRefreshSec',2),@('ExpectPublicDnsAnswers',$true))){if(-not $cfg.ContainsKey($pair[0])){$cfg[$pair[0]]=$pair[1]}}
    if(-not $cfg.ContainsKey('AllowedPrivateDnsNames')){$cfg.AllowedPrivateDnsNames=@()}
    if(-not $cfg.ContainsKey('LanTargets')){$cfg.LanTargets=@()}
    if($cfg.EnableWebStatus -isnot [bool] -or $cfg.ExpectPublicDnsAnswers -isnot [bool] -or $cfg.WebStatusPort -lt 1024 -or $cfg.WebStatusPort -gt 65535 -or $cfg.WebStatusRefreshSec -lt 1 -or $cfg.WebStatusRefreshSec -gt 5){throw 'Invalid web/DNS policy settings.'}
    if(@($cfg.LanTargets | Where-Object{-not $_.IP -or $_.Name -in @('sensor','upstream')}).Count){throw 'LAN targets require an IP and cannot use reserved topology identifiers.'}
    if(@($cfg.LanTargets).Count -gt 16 -or @($cfg.LanTargets | Where-Object{$_.Name -notmatch '^[A-Za-z0-9_.-]{1,40}$'}).Count){throw 'LAN targets need unique safe names, maximum 16.'}
    if(@($cfg.LanTargets.Name | Sort-Object -Unique).Count -ne @($cfg.LanTargets).Count){throw 'Duplicate LAN target names.'}
    foreach($name in $cfg.AllowedPrivateDnsNames){if($name -notmatch '^[A-Za-z0-9.-]{1,253}$'){throw 'Invalid DNS policy exemption name.'}}
    $cfg.EvidenceEpochMs=0L
    if($cfg.SENSOR_ROLE -notin @('DIRECT_BGW','BEHIND_ASUS','GENERIC')){throw 'SENSOR_ROLE must be DIRECT_BGW, BEHIND_ASUS or GENERIC.'}
    if($cfg.PingConcurrency -notin @(3,4) -or $cfg.PingStaggerMs -lt 50 -or $cfg.PingStaggerMs -gt 100){throw 'ICMP requires concurrency 3..4 and staggering 50..100 ms.'}
    if($cfg.SummaryIntervalSec -lt 30 -or $cfg.SummaryIntervalSec -gt 60){throw 'SummaryIntervalSec must be 30..60.'}
    if($cfg.CoordinatorGapThresholdSec -lt 2 -or $cfg.CoordinatorGapThresholdSec -gt 600){throw 'CoordinatorGapThresholdSec must be 2..600 seconds.'}
    if($cfg.HeartbeatIntervalSec -lt 60 -or $cfg.HeartbeatIntervalSec -gt 3600){throw 'HeartbeatIntervalSec must be 60..3600 seconds.'}
    if($cfg.IdleSummaryIntervalSec -lt 60 -or $cfg.IdleSummaryIntervalSec -gt 3600){throw 'IdleSummaryIntervalSec must be 60..3600 seconds.'}
    if($cfg.PersistPeriodicHealthCsv -isnot [bool] -or $cfg.LogAdvisoryAssessmentChanges -isnot [bool]){throw 'PersistPeriodicHealthCsv and LogAdvisoryAssessmentChanges must be boolean.'}
    if($cfg.AdvisoryLogCooldownSec -lt 10 -or $cfg.AdvisoryLogCooldownSec -gt 3600){throw 'AdvisoryLogCooldownSec must be 10..3600 seconds.'}
    foreach($key in @('RingBufferMinutes','IncidentPreMinutes','IncidentPostMinutes')){if($cfg[$key] -lt 0 -or $cfg[$key] -gt 60 -or [double]::IsNaN([double]$cfg[$key])){throw ($key+' must be 0..60 minutes.')}}
    if($cfg.RingBufferMinutes -lt 1 -or $cfg.IncidentPreMinutes -gt $cfg.RingBufferMinutes){throw 'RingBufferMinutes must be >=1 and cover IncidentPreMinutes.'}
    foreach($key in @('HealthySummaryIntervalSec','StorageMaintenanceSec')){if($cfg[$key] -lt 30 -or $cfg[$key] -gt 3600){throw ($key+' must be 30..3600 seconds.')}}
    foreach($key in @('HealthyRetentionDays','EventRetentionDays','IncidentRetentionDays','PacketCaptureRetentionDays','RunRetentionDays')){if($cfg[$key] -lt 1 -or $cfg[$key] -gt 3650){throw ($key+' must be 1..3650 days.')}}
    foreach($key in @('RingBufferMaxMB','IncidentTelemetryMaxMB','NormalLogMaxMB','PacketCaptureMaxMB')){if($cfg[$key] -lt 1 -or $cfg[$key] -gt 1024){throw ($key+' must be 1..1024 MB.')}}
    if($cfg.RingBufferMaxRecords -lt 100 -or $cfg.RingBufferMaxRecords -gt 100000){throw 'RingBufferMaxRecords must be 100..100000.'}
    if($cfg.StorageQuotaGB -lt 0.25 -or $cfg.StorageQuotaGB -gt 1024 -or $cfg.StorageReserveMB -lt 8 -or $cfg.StorageReserveMB*1MB -ge $cfg.StorageQuotaGB*1GB/4){throw 'Invalid storage quota/reserve (quota >=0.25 GB, reserve >=8 MB and <25% quota).'}
    if($cfg.PacketCaptureMaxMB*1MB+5MB -gt $cfg.StorageQuotaGB*1GB-$cfg.StorageReserveMB*1MB){throw 'Capture plus evidence budget must fit outside storage reserve.'}
    if($cfg.CompressAfterHours -lt 0 -or $cfg.CompressAfterHours -gt 8760 -or $cfg.CompressClosedIncidents -isnot [bool]){throw 'Invalid compression settings.'}
    if($cfg.EnablePushover -isnot [bool] -or $cfg.AlertOnRecovery -isnot [bool] -or $cfg.PushoverDevice -notmatch '^[A-Za-z0-9_-]{0,25}$'){throw 'Invalid Pushover enabled/recovery/device setting.'}
    if($cfg.AlertIncidentDelaySec -lt 0 -or $cfg.AlertIncidentDelaySec -gt 300 -or $cfg.AlertCooldownSec -lt 10 -or $cfg.AlertCooldownSec -gt 3600 -or $cfg.AlertMaxPerHour -lt 1 -or $cfg.AlertMaxPerHour -gt 60 -or $cfg.AlertMaxPending -lt 1 -or $cfg.AlertMaxPending -gt 32){throw 'Invalid notification hold/cooldown/rate/queue limit.'}
    if($cfg.AlertExpiryHours -lt 1 -or $cfg.AlertExpiryHours -gt 72 -or $cfg.AlertRetryInitialSec -lt 10 -or $cfg.AlertRetryMaxSec -lt $cfg.AlertRetryInitialSec -or $cfg.AlertRetryMaxSec -gt 3600 -or $cfg.AlertRequestTimeoutSec -lt 2 -or $cfg.AlertRequestTimeoutSec -gt 15 -or $cfg.AlertShutdownWaitSec -lt 0 -or $cfg.AlertShutdownWaitSec -gt 15 -or $cfg.AlertFaultCooldownSec -lt 60 -or $cfg.AlertFaultCooldownSec -gt 86400){throw 'Invalid notification retry/expiry/timeout settings.'}
    if($cfg.AlertIncidentPriority -notin @(0,1) -or $cfg.AlertRecoveryPriority -notin @(-1,0) -or @($cfg.AlertFaultTypes | Where-Object{$_ -notin @('FATAL','RECORDER_LIMIT','STORAGE_WARNING','CAPTURE_FAILED','SENSOR_GAP')}).Count){throw 'Invalid notification priority/fault types.'}
    foreach($name in @('PingTimeoutMs','DnsTimeoutMs','TcpConnectTimeoutMs')){if($cfg[$name] -lt 100 -or $cfg[$name] -gt 10000){throw "$name must be 100..10000 ms."}}
    if($cfg.HttpsTimeoutSec -lt 1 -or $cfg.HttpsTimeoutSec -gt 15){throw 'HttpsTimeoutSec must be 1..15.'}
    if($cfg.EventDebounceSec -lt 2 -or $cfg.RecoveryHoldSec -lt 2 -or $cfg.EvidenceWindowSec -lt $cfg.CorrelationWindowSec -or $cfg.CorrelationWindowSec -lt 2){throw 'Invalid debounce/evidence windows.'}
    if($cfg.DashboardIntervalMs -lt 100 -or $cfg.DashboardIntervalMs -gt 5000){throw 'DashboardIntervalMs must be 100..5000.'}
    if($cfg.TraceBudgetSec -lt 1 -or $cfg.TraceBudgetSec -gt 25 -or $cfg.TraceMaxHops -lt 1 -or $cfg.TraceMaxHops -gt 30){throw 'Trace budget must be 1..25 seconds and max hops 1..30.'}
    if($cfg.PacketCaptureSec -lt 1 -or $cfg.PacketCaptureSec -gt 300 -or $cfg.CaptureCooldownSec -lt $cfg.PacketCaptureSec){throw 'Invalid packet capture duration/cooldown.'}
    foreach($ip in @($cfg.GatewayIP,$cfg.SystemDnsIP,$cfg.BgwManagementIP)+@($cfg.TraceTargets)+@($cfg.PublicTargets.IP)+@($cfg.DnsResolvers.IP)+@($cfg.DnsTransportResolvers.IP)+@($cfg.MtuTargets.IP)+@($cfg.LanTargets.IP)){
        if(-not $ip){continue};$address=$null
        if(-not [Net.IPAddress]::TryParse($ip,[ref]$address) -or $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){throw "Invalid IPv4 address: $ip"}
    }
    foreach($key in @('PublicTargets','DnsResolvers','HttpsSites','TcpConnectTargets','DnsTransportResolvers','MtuTargets','DnsNames','TraceTargets')){
        if(@($cfg[$key]).Count -eq 0){throw "Empty target list: $key"}
        if(@($cfg[$key]).Count -gt 24){throw "Too many targets: $key (maximum 24)."}
        if($key -ne 'DnsNames' -and $key -ne 'TraceTargets'){
            $names=@($cfg[$key] | ForEach-Object{$_.Name})
            if(@($names | Sort-Object -Unique).Count -ne $names.Count -or @($names | Where-Object{-not $_}).Count -gt 0){throw "Duplicate/empty names in $key."}
        }
    }
    foreach($site in $cfg.HttpsSites){$url=$null;if(-not [uri]::TryCreate($site.Url,[UriKind]::Absolute,[ref]$url) -or $url.Scheme -ne 'https' -or $site.Url -match '["\r\n]'){throw 'HTTPS URLs must be absolute HTTPS URLs without quotes/newlines.'}}
    foreach($target in $cfg.TcpConnectTargets){if($target.Port -lt 1 -or $target.Port -gt 65535 -or $target.HostName -notmatch '^[A-Za-z0-9.-]+$'){throw 'Invalid TCP target.'}}
    if(@($cfg.MtuPayloadSizes).Count -gt 8 -or @($cfg.MtuPayloadSizes | Where-Object{$_ -lt 1 -or $_ -gt 65500}).Count){throw 'Invalid MTU payload sizes.'}
    $phases=@{}
    foreach($name in @('ICMP','DNS','TCP443','HTTPS','NIC','TCP_STATS','DNS_TRANSPORT','MTU','TRACE')){
        $s=$cfg.Schedules[$name]
        if(-not $s -or $s.IntervalSec -lt 3 -or $s.PhaseMs -lt 0 -or $s.PhaseMs -ge $s.IntervalSec*1000){throw "Invalid schedule: $name"}
        if($s.Enabled){if($phases.ContainsKey([int]$s.PhaseMs)){throw 'Enabled families must have distinct startup phases.'};$phases[[int]$s.PhaseMs]=$true}
    }
    return $cfg
}

function Get-SensorContext {
    param($Config)
    $routes=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Where-Object{$_.NextHop -and $_.NextHop -ne '0.0.0.0' -and ($Config.InterfaceIndex -eq 0 -or $_.InterfaceIndex -eq $Config.InterfaceIndex)})
    $ranked=@(foreach($route in $routes){
        $iface=Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop
        [pscustomobject]@{Route=$route;Metric=([int]$route.RouteMetric+[int]$iface.InterfaceMetric)}
    })
    $best=$ranked | Sort-Object Metric | Select-Object -First 1
    $index=if($best){$best.Route.InterfaceIndex}else{$Config.InterfaceIndex}
    if(-not $index){throw 'No IPv4 default route; configure InterfaceIndex and GatewayIP for an initially offline sensor.'}
    $adapter=Get-NetAdapter -InterfaceIndex $index -ErrorAction Stop
    $gateway=if($Config.GatewayIP){$Config.GatewayIP}elseif($best){$best.Route.NextHop}else{''}
    if(-not $gateway){throw 'No gateway available; configure GatewayIP.'}
    $dns=if($Config.SystemDnsIP){$Config.SystemDnsIP}else{@((Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses)[0]}
    if(-not $dns){throw 'No configured IPv4 DNS server; set SystemDnsIP.'}
    $info=[pscustomobject]@{Gateway=$gateway;InterfaceIndex=$index;AdapterName=$adapter.Name;LinkSpeed=[string]$adapter.LinkSpeed;SystemDns=$dns}
    $targets=@([pscustomobject]@{Name='Default-Gateway';IP=$gateway;Provider='Local';Role='Gateway'})
    if($Config.EnableBgwProbe -and $Config.SENSOR_ROLE -in @('DIRECT_BGW','BEHIND_ASUS') -and $gateway -ne $Config.BgwManagementIP){$targets+= [pscustomobject]@{Name='AT&T-BGW320';IP=$Config.BgwManagementIP;Provider='Local';Role='Gateway2'}}
    $targets+=@($Config.LanTargets | ForEach-Object{[pscustomobject]@{Name=$_.Name;IP=$_.IP;Provider='LAN';Role='LAN'}})
    $targets+=@($Config.PublicTargets | ForEach-Object{[pscustomobject]$_})
    if(@($targets.Name | Sort-Object -Unique).Count -ne $targets.Count){throw 'Duplicate ICMP names across gateway, BGW, LAN and public targets.'}
    if(@($targets.IP | Sort-Object -Unique).Count -ne $targets.Count){throw 'Duplicate ICMP IPs; remove public targets that equal local gateway/BGW addresses.'}
    $dnsRole=$Config.SystemDnsRole
    if($dnsRole -eq 'AUTO'){
        $dnsRole=if($Config.SENSOR_ROLE -ne 'GENERIC' -and $dns -eq $Config.BgwManagementIP){'BGW'}elseif($dns -eq $gateway -and $Config.SENSOR_ROLE -ne 'DIRECT_BGW'){'ROUTER'}else{'EXTERNAL'}
    }
    if($dnsRole -notin @('BGW','ROUTER','EXTERNAL')){throw 'SystemDnsRole must be AUTO, ROUTER, BGW or EXTERNAL.'}
    $scope=switch($dnsRole){BGW{'BgwDNS'}ROUTER{'RouterDNS'}EXTERNAL{'ExternalDNS'}}
    $match=$Config.DnsResolvers | Where-Object{$_.IP -eq $dns} | Select-Object -First 1
    $systemProvider=if($dnsRole -ne 'EXTERNAL'){$dnsRole}elseif($match -and $match.Class -eq 'ATT'){'ATT'}elseif($match -and $match.Provider){$match.Provider}elseif($match){$match.Name}else{'DNS@'+$dns}
    $resolvers=@([pscustomobject]@{Name='System-Default';IP=$dns;Class='System';Scope=$scope;Provider=$systemProvider})
    foreach($d in $Config.DnsResolvers){$resolvers+=[pscustomobject]@{Name=$d.Name;IP=$d.IP;Class=$d.Class;Provider=if($d.Class -eq 'ATT'){'ATT'}elseif($d.Provider){$d.Provider}else{$d.Name};Scope='ExternalDNS'}}
    # Optional local DNS services require explicit opt-in; always measure system DNS.
    if($Config.SENSOR_ROLE -eq 'BEHIND_ASUS'){
        if($Config.EnableRouterDnsProbe -and $dns -ne $gateway){$resolvers+=[pscustomobject]@{Name='ASUS-Proxy';IP=$gateway;Class='Router';Provider='Router';Scope='RouterDNS'}}
        if($Config.EnableBgwDnsProbe -and $dns -ne $Config.BgwManagementIP){$resolvers+=[pscustomobject]@{Name='BGW-Proxy';IP=$Config.BgwManagementIP;Class='BGW';Provider='BGW';Scope='BgwDNS'}}
    }elseif($Config.SENSOR_ROLE -eq 'DIRECT_BGW' -and $Config.EnableBgwDnsProbe -and $dns -ne $Config.BgwManagementIP){$resolvers+=[pscustomobject]@{Name='BGW-Proxy';IP=$Config.BgwManagementIP;Class='BGW';Provider='BGW';Scope='BgwDNS'}}
    $transport=@($Config.DnsTransportResolvers | ForEach-Object{[pscustomobject]@{Name=$_.Name;IP=$_.IP;Class=$_.Class;Provider=if($_.Class -eq 'ATT'){'ATT'}else{$_.Name};Scope='ExternalDNS'}})
    [pscustomobject]@{RouteInfo=$info;Targets=$targets;AllDnsResolvers=$resolvers;TransportResolvers=$transport;SystemDnsRole=$dnsRole;CurlExe=(Get-Command curl.exe -ErrorAction SilentlyContinue | Select-Object -First 1).Source}
}

function New-LatencyStats {
    [pscustomobject]@{Sent=0;Received=0;Lost=0;Sum=0.0;Min=[double]::PositiveInfinity;Max=0.0;Last=$null;LastStatus='STARTING';LastQuery='';AnswerAnomalies=0L;LastAnswerPolicy='WAITING';LastAddresses=@();History=(New-Object System.Collections.ArrayList)}
}

function Initialize-DisplayState {
    $script:PingStats=@{};foreach($t in $Targets){$script:PingStats[$t.IP]=New-LatencyStats}
    $script:DnsStats=@{};foreach($d in $AllDnsResolvers){$script:DnsStats[$d.Name]=New-LatencyStats}
    $script:HttpsStats=@{};foreach($h in $HttpsSites){$script:HttpsStats[$h.Name]=[pscustomobject]@{Sent=0;Good=0;Failed=0;LastTotal=$null;LastDNS=$null;LastTCP=$null;LastTLS=$null;LastTTFB=$null;LastCode='';LastStatus='STARTING';LastStage='';LastRemoteIP='';LastExitCode=0;History=(New-Object System.Collections.ArrayList)}}
    $script:TcpConnectStats=@{};foreach($t in $TcpConnectTargets){$script:TcpConnectStats[$t.Name]=[pscustomobject]@{Sent=0;Attempts=0;Good=0;Failed=0;DnsFailed=0;AnswerBlocked=0;LastDNS=$null;LastConnect=$null;LastIP='';LastStatus='STARTING';LastStage='';History=(New-Object System.Collections.ArrayList)}}
    $script:DnsTransportStats=@{};foreach($d in $DnsTransportResolvers){$script:DnsTransportStats[$d.Name]=[pscustomobject]@{LastUDP='-';LastUDPms=$null;LastTCP53='-';LastTCP53ms=$null;LastDoH='N/A';LastDoHms=$null;LastDoHHttp='';History=(New-Object System.Collections.ArrayList)}}
    $script:TcpStatsCurrent=$null;$script:TcpStatsPrevious=$null;$script:TcpStatsDelta=$null
    $script:TrafficHistory=New-Object System.Collections.ArrayList;$script:NicMonoMs=$null;
    $script:NicCurrent=$null;$script:NicPrevious=$null;$script:NicDelta=$null
    $script:RouteSignature=$null;$script:RouteChangedAt=$null;$script:MtuLatest=@{}
    $script:WatchLogAt=@{};$script:WatchLoggedActive=@{};$script:GapDiscarded=0L;$script:WatchActive=@{};$script:RecentHistory=New-Object System.Collections.ArrayList
    $script:DnsFallbacks=@{};$script:DnsFallbackOmitted=0L;$script:FailureStages=@{};$script:FailureStageOmitted=0L;$script:AdvisoryCounters=@{};$script:AdvisoryKeysOmitted=0L;$script:ProcessResources=$null;$script:ResourcePrevious=$null
    $script:Latest=@{};$script:FamilyAvailability=@{};$script:IncidentCount=0;$script:ActiveEventCode=$null
    $script:LastErrorTime=$null;$script:LastErrorText='No incident recorded in this run.';$script:LastErrorState='CLEAR'
    $script:DashboardInitialized=$false;$script:DashboardFrame=@();$script:FatalErrorMessage=$null
}

function Open-RunLogs {
    $script:Writers=@{}
    $script:CsvHeaders=@{};$script:LogPaths=@{}
}

function Write-CsvRecord {
    param([string]$File,$Record)
    $lines=@($Record | ConvertTo-Csv -NoTypeInformation)
    Write-RunLogLine $File $lines[1] $lines[0]
}

function Write-HistoryLog {
    param([string]$Type,[string]$Message)
    $utc=[datetime]::UtcNow
    $line=('{0} UTC={1} Sensor={2} Role={3} Run={4} {5} {6}' -f $utc.ToLocalTime().ToString('o'),$utc.ToString('o'),$Cfg.SENSOR_NAME,$Cfg.SENSOR_ROLE,$RunId,$Type,$Message)
    Write-RunLogLine 'Network_History.log' $line
    [void]$script:RecentHistory.Add(('{0} {1} {2}' -f $utc.ToLocalTime().ToString('HH:mm:ss'),$Type,$Message))
    while($script:RecentHistory.Count -gt 5){$script:RecentHistory.RemoveAt(0)}
}

function Write-EventLog {
    param([string]$Message,[string]$Type='EVENT',$Assessment=$null,$Details=$null)
    $utc=[datetime]::UtcNow
    $record=[ordered]@{SchemaVersion=1;TimestampUTC=$utc.ToString('o');Timestamp=$utc.ToLocalTime().ToString('o');SensorName=$Cfg.SENSOR_NAME;SensorRole=$Cfg.SENSOR_ROLE;RunId=$RunId;MonoMs=$Clock.ElapsedMilliseconds;Type=$Type;Message=$Message}
    if($Assessment){
        $record.Classification=$Assessment.Code;$record.Confidence=$Assessment.Confidence
        $record.Protocols=$Assessment.Protocols;$record.Providers=$Assessment.Providers
        $record.EvidenceIds=$Assessment.EvidenceIds;$record.Evidence=@($Assessment.Evidence | Select-Object EvidenceId,Family,Protocol,Name,Provider,Scope,StartedUTC,CompletedUTC,StartMonoMs,EndMonoMs,Status,Stage,Data)
        $record.SharedEventCandidate=$Assessment.SharedEventCandidate;$record.SharedEventStatus=$Assessment.SharedEventStatus
        $record.EpisodeId=$State.EpisodeId
    }
    if($Details){$record.Details=$Details}
    Write-RunLogLine 'Events.jsonl' ($record | ConvertTo-Json -Compress -Depth 7)
    Write-RunLogLine 'Events.log' ('{0} UTC={1} Sensor={2} Role={3} Run={4} {5} {6}' -f $record.Timestamp,$record.TimestampUTC,$Cfg.SENSOR_NAME,$Cfg.SENSOR_ROLE,$RunId,$Type,$Message)
    Write-HistoryLog $Type $Message
    Receive-NotificationEvent $Type $Message $Assessment
}

function Get-RecentNetworkHistory {param([int]$Count=5);return @($script:RecentHistory | Select-Object -Last $Count)}

function Update-LatencyStats {
    param($Stats,$Row)
    $Stats.Sent++;$ok=$Row.Status -eq 'OK'
    if($ok){$Stats.Received++;$Stats.Sum+=$Row.LatencyMs;$Stats.Min=[math]::Min($Stats.Min,$Row.LatencyMs);$Stats.Max=[math]::Max($Stats.Max,$Row.LatencyMs);$Stats.Last=$Row.LatencyMs;$Stats.LastStatus='OK'}else{$Stats.Lost++;$Stats.Last=$null;$Stats.LastStatus=$Row.Stage}
    Add-HistorySample $Stats.History $ok $Row.LatencyMs $Row.Stage ([datetime]$Row.CompletedUTC)
}

function Get-CounterDelta {
    param($Current,$Previous,[string[]]$Names)
    $delta=@{}
    foreach($name in $Names){$delta[$name]=if($Previous -and $Current[$name] -ge $Previous[$name]){[long]$Current[$name]-[long]$Previous[$name]}else{0L}}
    return $delta
}

function Get-InterfaceTrafficDelta {
    param($Current,$Previous,[long]$NowMs,$PreviousMs,[double]$MaxGapSec=30)
    $result=[pscustomobject]@{RxMbps=$null;TxMbps=$null;CounterState='BASELINE'}
    if(-not $Previous -or $null -eq $PreviousMs){return $result}
    if($NowMs -le $PreviousMs){$result.CounterState='INVALID_CLOCK';return $result}
    if($Current.Name -ne $Previous.Name -or $Current.RxBytes -lt $Previous.RxBytes -or $Current.TxBytes -lt $Previous.TxBytes){$result.CounterState='RESET_OR_INTERFACE_CHANGE';return $result}
    $seconds=($NowMs-[long]$PreviousMs)/1000.0
    if($seconds -gt $MaxGapSec){$result.CounterState='SAMPLING_GAP';return $result}
    $result.RxMbps=[math]::Round(8*([long]$Current.RxBytes-[long]$Previous.RxBytes)/$seconds/1e6,3)
    $result.TxMbps=[math]::Round(8*([long]$Current.TxBytes-[long]$Previous.TxBytes)/$seconds/1e6,3)
    $result.CounterState='DELTA';return $result
}

function Receive-Observation {
    param($Row)
    if($Cfg.EvidenceEpochMs -and $Row.StartMonoMs -lt $Cfg.EvidenceEpochMs){$script:GapDiscarded++;return}
    Add-FailureStageCount $Row;Add-DnsFallbackCount $Row
    $d=$Row.Data;$utc=(Convert-MonitorUtc $Row.CompletedUTC)
    $rowFields=[ordered]@{SchemaVersion=1;Timestamp=$utc.ToLocalTime().ToString('o');TimestampUTC=$utc.ToString('o');SensorName=$Cfg.SENSOR_NAME;SensorRole=$Cfg.SENSOR_ROLE;RunId=$RunId;EvidenceId=$Row.EvidenceId;SweepId=$Row.SweepId;Family=$Row.Family;Protocol=$Row.Protocol;Name=$Row.Name;Provider=$Row.Provider;Scope=$Row.Scope;StartedUTC=$Row.StartedUTC;StartMonoMs=$Row.StartMonoMs;EndMonoMs=$Row.EndMonoMs;Status=$Row.Status;Stage=$Row.Stage;LatencyMs=$Row.LatencyMs}
    $key=$Row.Family+':'+$Row.Protocol+':'+$Row.Name
    if($Row.Protocol -in @('DNS_UDP','DNS_TCP')){$key+=':'+$d.QueryName}
    if($Row.Protocol -eq 'ICMP_DF'){$key+=':'+$d.PayloadBytes}
    $script:Latest[$key]=$Row;$script:FamilyAvailability[$Row.Family]=$Row.Status
    $legacy=[ordered]@{}+$rowFields;$file=$null
    if($Row.Protocol -in @('DNS_UDP','DNS_TCP')){$legacy.Addresses=@($d.Addresses) -join ';';$legacy.AnswerPolicy=$d.AnswerPolicy}
    switch($Row.Protocol){
        ICMP {
            $file='Ping.csv';$legacy.IP=$d.IP;$legacy.Role=$Row.Scope
            Update-LatencyStats $PingStats[$d.IP] $Row
            if($Row.Status -eq 'OK'){$PingStats[$d.IP].LastStatus=if($Row.LatencyMs -ge 100){'HIGH'}elseif($Row.LatencyMs -ge 50){'ELEVATED'}else{'OK'}}
        }
        DNS_UDP {
            if($Row.Family -eq 'DNS'){
                $file='DNS.csv';$legacy.Resolver=$Row.Name;$legacy.ServerIP=$d.IP;$legacy.QueryName=$d.QueryName;$legacy.RCode=$d.RCode
                Update-LatencyStats $DnsStats[$Row.Name] $Row;$DnsStats[$Row.Name].LastQuery=$d.QueryName
                $DnsStats[$Row.Name].LastStatus=if($Row.Status -ne 'OK'){'FAIL'}elseif($Row.LatencyMs -ge 750){'HIGH'}elseif($Row.LatencyMs -ge 250){'SLOW'}else{'OK'}
                $policy=Get-DnsAnswerPolicy $d.QueryName $d.Addresses $Cfg
                $DnsStats[$Row.Name].LastAnswerPolicy=$policy;$DnsStats[$Row.Name].LastAddresses=@($d.Addresses)
                if($policy -eq 'PUBLIC_NAME_NONPUBLIC_ANSWER'){$DnsStats[$Row.Name].AnswerAnomalies++;$DnsStats[$Row.Name].LastStatus='ANSWER_ANOMALY'}
                $script:LastDnsName=$d.QueryName
            }else{$file='DNS_Transport.csv';$s=$DnsTransportStats[$Row.Name];$s.LastUDP=$Row.Status;$s.LastUDPms=$Row.LatencyMs;$legacy.ServerIP=$d.IP;$legacy.QueryName=$d.QueryName;$legacy.RCode=$d.RCode}
        }
        DNS_TCP {$file='DNS_Transport.csv';$s=$DnsTransportStats[$Row.Name];$s.LastTCP53=$Row.Status;$s.LastTCP53ms=$Row.LatencyMs;$legacy.ServerIP=$d.IP;$legacy.QueryName=$d.QueryName;$legacy.RCode=$d.RCode}
        DOH_ENDPOINT {$file='DNS_Transport.csv';$s=$DnsTransportStats[$Row.Name];$s.LastDoH=if($Row.Status -eq 'UNAVAILABLE'){'N/A'}else{$Row.Status};$s.LastDoHms=$Row.LatencyMs;$s.LastDoHHttp=$d.HttpCode;$legacy.ServerIP='';$legacy.QueryName='';$legacy.RCode=$Row.Stage}
        TCP443 {
            $file='TCP443.csv';$s=$TcpConnectStats[$Row.Name];$s.Sent++
            $s.LastStatus=$Row.Status;$s.LastStage=$Row.Stage;$s.LastDNS=$d.DNSms;$s.LastConnect=$Row.LatencyMs;$s.LastIP=$d.IP
            if($d.TcpAttempted){$s.Attempts++;if($Row.Status -eq 'OK'){$s.Good++}else{$s.Failed++};Add-HistorySample $s.History ($Row.Status -eq 'OK') $Row.LatencyMs $Row.Stage ([datetime]$Row.CompletedUTC)}elseif($Row.Stage -eq 'DNS_ANSWER_NONPUBLIC'){$s.AnswerBlocked++}else{$s.DnsFailed++}
            $legacy.HostName=$d.HostName;$legacy.ResolvedIP=$d.IP;$legacy.DNSms=$d.DNSms;$legacy.Port=$d.Port;$legacy.ConnectMs=$Row.LatencyMs;$legacy.TcpAttempted=$d.TcpAttempted;$legacy.FailureStage=$Row.Stage
        }
        HTTPS {
            $file='HTTPS.csv';$s=$HttpsStats[$Row.Name];$s.LastStatus=$Row.Status;$s.LastStage=$Row.Stage;$s.LastDNS=$d.DNSms;$s.LastTCP=$d.TCPms;$s.LastTLS=$d.TLSms;$s.LastTTFB=$d.TTFBms;$s.LastTotal=$Row.LatencyMs;$s.LastCode=$d.HttpCode;$s.LastRemoteIP=$d.IP;$s.LastExitCode=$d.ExitCode
            if($Row.Status -ne 'UNAVAILABLE'){$s.Sent++;if($Row.Status -eq 'OK'){$s.Good++}else{$s.Failed++};Add-HistorySample $s.History ($Row.Status -eq 'OK') $Row.LatencyMs $Row.Stage ([datetime]$Row.CompletedUTC)}
            $legacy.URL=$d.URL;$legacy.HttpMethod=$d.HttpMethod;$legacy.Measurement=$d.Measurement;$legacy.FailureStage=$Row.Stage;$legacy.CurlExitCode=$d.ExitCode;$legacy.RemoteIP=$d.IP;$legacy.HttpCode=$d.HttpCode;$legacy.DNSms=$d.DNSms;$legacy.TCPms=$d.TCPms;$legacy.TLSms=$d.TLSms;$legacy.TTFBms=$d.TTFBms;$legacy.TotalMs=$Row.LatencyMs
        }
        NIC {
            $file='NIC.csv'
            if($Row.Status -ne 'UNAVAILABLE'){
                $delta=Get-CounterDelta $d $script:NicCurrent @('RxErrors','TxErrors','RxDrops','TxDrops');foreach($n in $delta.Keys){$d['d'+$n]=$delta[$n]}
                $rate=Get-InterfaceTrafficDelta $d $script:NicCurrent $Row.EndMonoMs $script:NicMonoMs ([math]::Max($Cfg.CoordinatorGapThresholdSec,3*$Cfg.Schedules.NIC.IntervalSec))
                $d.RxMbps=$rate.RxMbps;$d.TxMbps=$rate.TxMbps;$d.CounterState=$rate.CounterState
                $script:NicMonoMs=[long]$Row.EndMonoMs
                [void]$script:TrafficHistory.Add([pscustomobject]@{monoMs=$Row.EndMonoMs;rxMbps=$d.RxMbps;txMbps=$d.TxMbps})
                while($script:TrafficHistory.Count -gt 120){$script:TrafficHistory.RemoveAt(0)}
                $script:NicPrevious=$script:NicCurrent;$script:NicCurrent=$d;$script:NicDelta=[pscustomobject]$delta
            }
            foreach($n in @('LinkSpeed','RxErrors','TxErrors','RxDrops','TxDrops','RxBytes','TxBytes','dRxErrors','dTxErrors','dRxDrops','dTxDrops')){$legacy[$n]=$d[$n]};$legacy.Adapter=$d.Name
        }
        TCP_STATS {
            $file='TCP_Stats.csv'
            if($Row.Status -eq 'OK'){
                $delta=Get-CounterDelta $d $script:TcpStatsCurrent @('SegmentsRetransmitted','FailedConnectionAttempts','ResetConnections','ErrorsReceived')
                $script:TcpStatsPrevious=$script:TcpStatsCurrent;$script:TcpStatsCurrent=$d
                $script:TcpStatsDelta=[pscustomobject]@{Retrans=$delta.SegmentsRetransmitted;Failed=$delta.FailedConnectionAttempts;Resets=$delta.ResetConnections;Errors=$delta.ErrorsReceived}
                $d.dRetrans=$delta.SegmentsRetransmitted;$d.dFailed=$delta.FailedConnectionAttempts;$d.dResets=$delta.ResetConnections;$d.dErrors=$delta.ErrorsReceived
            }
            foreach($n in @('SegmentsSent','SegmentsReceived','SegmentsRetransmitted','FailedConnectionAttempts','ResetConnections','ErrorsReceived','dRetrans','dFailed','dResets','dErrors')){$legacy[$n]=$d[$n]}
        }
        ICMP_DF {$file='MTU.csv';$legacy.Target=$Row.Name;$legacy.IP=$d.IP;$legacy.PayloadBytes=$d.PayloadBytes;$legacy.DF=$d.DF;$script:MtuLatest[$Row.Name+':'+$d.PayloadBytes]=$Row}
        TRACE {
            $file='Route_Changes.log'
            $metadata='{0} UTC={1} Sensor={2} Role={3} Run={4} Stage={5}' -f $legacy.Timestamp,$legacy.TimestampUTC,$Cfg.SENSOR_NAME,$Cfg.SENSOR_ROLE,$RunId,$Row.Stage
            if($Row.Name -eq $Cfg.TraceTargets[0] -and $Row.Stage -eq 'COMPLETE' -and $d.Signature){
                if($script:RouteSignature -and $script:RouteSignature -ne $d.Signature){$script:RouteChangedAt=$utc.ToLocalTime();Write-EventLog ('Traceroute replies changed for '+$Row.Name+': '+$script:RouteSignature+' -> '+$d.Signature+'. Missing replies and load balancing can change this observation; routing change is unproven.') 'TRACE_OBSERVATION_CHANGE'}
                $script:RouteSignature=$d.Signature
            }
        }
    }
    $rowFields.DataJSON=$d | ConvertTo-Json -Compress -Depth 5
    Add-RingTelemetry ([pscustomobject]$rowFields) ([pscustomobject]$legacy) $file
}

function Write-AtomicText {
    param([string]$Path,[string]$Text)
    $tmp=$Path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    try{
        [IO.File]::WriteAllText($tmp,$Text,([Text.UTF8Encoding]::new($true)))
        for($attempt=0;$attempt -lt 3;$attempt++){
            try{if([IO.File]::Exists($Path)){[IO.File]::Replace($tmp,$Path,[System.Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($tmp,$Path)};return}catch{if($attempt -eq 2){throw};Start-Sleep -Milliseconds 50}
        }
    }finally{if([IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)}}
}

function Write-RunSummary {
    param([string]$Kind='LIVE')
    $utc=[datetime]::UtcNow;$lines=New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('NETWORK DIAGNOSTIC MONITOR V2.12-RC3.1 - '+$Kind+' SUMMARY')
    $lines.Add(('Sensor: {0} Role: {1} Run: {2}' -f $Cfg.SENSOR_NAME,$Cfg.SENSOR_ROLE,$RunId))
    $lines.Add(('Started UTC: {0} Local: {1}' -f $StartTime.ToUniversalTime().ToString('o'),$StartTime.ToString('o')))
    $lines.Add(('Updated UTC: {0} Local: {1} MonotonicMs: {2}' -f $utc.ToString('o'),$utc.ToLocalTime().ToString('o'),$Clock.ElapsedMilliseconds))
    $currentLink=Get-CurrentLinkSpeed
    $lines.Add(('Adapter: {0} Link: {1} Gateway: {2} SystemDNS: {3}' -f $RouteInfo.AdapterName,$(if($currentLink){$currentLink}else{'unknown / stale'}),$RouteInfo.Gateway,$RouteInfo.SystemDns))
    if($script:Continuity){
        $lines.Add(('SENSOR CONTINUITY: detected gaps={0}; coordinator gap time= {1:N1}s; longest gap={2:N1}s; clock corrections={3}' -f $Continuity.GapCount,($Continuity.BlindMs/1000),($Continuity.LongestGapMs/1000),$Continuity.ClockCorrectionCount))
        $lines.Add('NOTE: gaps mean missing monitor samples, NOT confirmed network downtime; no four-day uptime estimate from incomplete coverage.')
    }

    $health=Get-MonitorHealth $Assessment $State $Scheduler $Clock.ElapsedMilliseconds $Cfg
    $lines.Add(('NETWORK: {0}; PROBE EXECUTION: {1}; DEPLOYMENT: {2}; discarded gap-spanning rows={3}' -f $health.Network,$health.Probes,$script:DeploymentStatus,$script:GapDiscarded))
    $lines.Add(('Assessment: {0}; Active incident: {1}; Incidents: {2}' -f $Assessment.Code,$State.Active,$IncidentCount))
    $lines.Add(('Last error: {0} {1}; Fatal: {2}' -f $script:LastErrorState,$script:LastErrorText,$script:FatalErrorMessage))
    $lines.Add('');$lines.Add('PING CUMULATIVE RESULTS (ICMP loss is advisory without protocol corroboration)')
    foreach($t in $Targets){$s=$PingStats[$t.IP];$loss=if($s.Sent){[math]::Round(100*$s.Lost/$s.Sent,3)}else{0};$avg=if($s.Received){$s.Sum/$s.Received}else{$null};$lines.Add(('{0,-18} {1,-15} Sent={2} Recv={3} Loss={4}% Avg={5} Max={6}' -f $t.Name,$t.IP,$s.Sent,$s.Received,$loss,(Format-Num $avg 2),(Format-Num $(if($s.Received){$s.Max}else{$null}) 0)))}
    $lines.Add('');$lines.Add('DNS CUMULATIVE RESULTS')
    foreach($d in $AllDnsResolvers){$s=$DnsStats[$d.Name];$lines.Add(('{0,-16} {1,-15} Scope={2} Sent={3} Good={4} Failed={5}' -f $d.Name,$d.IP,$d.Scope,$s.Sent,$s.Received,$s.Lost))}
    foreach($d in $AllDnsResolvers){$s=$DnsStats[$d.Name];$lines.Add(('DNS answer policy: {0} Anomalies={1} Last={2} Addresses={3}' -f $d.Name,$s.AnswerAnomalies,$s.LastAnswerPolicy,($s.LastAddresses -join ',')))}
    $lines.Add('');$lines.Add('TCP/443 CONNECT RESULTS (DNS failures excluded from attempts and failure rate)')
    foreach($t in $TcpConnectTargets){$s=$TcpConnectStats[$t.Name];$pct=if($s.Attempts){[math]::Round(100*$s.Failed/$s.Attempts,3)}else{0};$lines.Add(('{0,-14} Queries={1} TCPAttempts={2} Good={3} TCPFailed={4} TCPFailPct={5}% DNSFailed={6} AnswerBlocked={7} LastStage={8}' -f $t.Name,$s.Sent,$s.Attempts,$s.Good,$s.Failed,$pct,$s.DnsFailed,$s.AnswerBlocked,$s.LastStage))}
    $lines.Add('');$lines.Add('HTTPS RESULTS')
    foreach($h in $HttpsSites){$s=$HttpsStats[$h.Name];$lines.Add(('{0,-14} Sent={1} Good={2} Failed={3} LastStage={4}' -f $h.Name,$s.Sent,$s.Good,$s.Failed,$s.LastStage))}
    $lines.Add('');$lines.Add('SCHEDULER (skips = busy/missed fixed-rate slots; no catch-up bursts)')
    if($Scheduler){foreach($job in $Scheduler.Jobs.Values){$lines.Add(('{0,-14} Started={1} Completed={2} Skipped={3} InFlight={4} ScheduledSlots={5} ScheduledStarts={6} RequestedStarts={7} Aborted={8} Failed={9}' -f $job.Name,$job.Sequence,$job.Completed,$job.Skipped,[bool]$job.Handle,$job.DeadlineSlots,$job.ScheduledStarts,$job.RequestedStarts,$job.Aborted,$job.Failed))}}
    $lines.Add(('TCP counters: '+($script:TcpStatsCurrent | ConvertTo-Json -Compress)));$lines.Add(('NIC counters: '+($script:NicCurrent | ConvertTo-Json -Compress)))
    $lines.Add(('MONITOR PROCESS (children excluded; CPU 100% = one logical CPU): '+((Get-ProcessResourceSnapshot) | ConvertTo-Json -Compress)))
    $lines.Add(('FAILURE STAGES (accepted probe rows; bounded, omitted='+$script:FailureStageOmitted+'): '+(@(Get-FailureStageSummary) | ConvertTo-Json -Compress)))
    $lines.Add(('NAMED TCP DNS FALLBACKS (UDP truncation; omitted='+$script:DnsFallbackOmitted+'): '+(@(Get-DnsFallbackSummary) | ConvertTo-Json -Compress)))
    $lines.Add(('ADVISORY TRANSITIONS (watch starts/clears, not failed-probe counts; omitted='+$script:AdvisoryKeysOmitted+'): '+(@(Get-AdvisorySummary) | ConvertTo-Json -Compress)))
    $lines.Add(('Packet capture enabled: {0}; Run directory: {1}' -f $PacketCaptureEnabled,$RunDir))
    $lines.Add(('STORAGE: accounted/reserved={0} bytes; quota={1}; pruned={2}; suppressed writes={3}' -f $Storage.Used,$Storage.Quota,$Storage.Pruned,$Storage.Dropped))
    $lines.Add(('RAM ring: records={0}; estimated payload bytes={1}; evicted={2}; target={3} min' -f $Ring.Count,$RingBytes,$RingEvicted,$Cfg.RingBufferMinutes))
    if($Kind -eq 'FINAL' -and $State.Active){$lines.Add('STOPPED WITH UNRESOLVED INCIDENT: '+$State.Active+'; closure is not recovery; duration is a lower bound.')}
    $lines.Add(('Ring expiry='+$script:RingExpired+'; capacity evictions='+$script:RingCapacityEvicted+' (evidence retention pressure)'))
    $lines.Add(('Recorder: {0}; telemetry bytes={1}; suppressed CSV rows={2}' -f $(if($Recorder){$Recorder.Path}else{'idle'}),$(if($Recorder){$Recorder.Bytes}else{0}),$(if($Recorder){$Recorder.Dropped}else{0})))
    if($script:Alerts){$lines.Add(('PUSHOVER: {0}; pending={1}; accepted={2}; failed attempts={3}; expired/dropped={4}; {5}' -f $Alerts.Mode,$Alerts.Pending.Count,$Alerts.Delivered,$Alerts.Failed,$Alerts.Dropped,$Alerts.LastStatus))}
    $path=Join-Path $RunDir ('Summary_'+$(if($Kind -eq 'LIVE'){'Live'}else{'Final'})+'.txt')
    if(-not (Write-ManagedText $path ($lines -join "`r`n") -Critical -Final)){throw ('Insufficient quota for '+$Kind+' summary.')}
}

function Get-LatestMtuStatus {
    $rows=@($script:MtuLatest.Values | Where-Object{$_.Data.PayloadBytes -eq 1472})
    if(-not $rows.Count){return [pscustomobject]@{State='WAITING';Text='No 1472-byte DF result yet.'}}
    $bad=@($rows | Where-Object{$_.Status -ne 'OK'})
    if($bad.Count){return [pscustomobject]@{State='WATCH';Text=('1472-byte DF: '+(($bad | ForEach-Object{$_.Name+':'+$_.Stage}) -join ', ')+'. Timeout alone does not prove MTU trouble.')}}
    return [pscustomobject]@{State='OK';Text='1472-byte DF passing on tested paths.'}
}

function Get-ForensicsStatus {
    $mtu=Get-LatestMtuStatus
    $health=Get-MonitorHealth $Assessment $State $Scheduler $Clock.ElapsedMilliseconds $Cfg
    @(
        [pscustomobject]@{Name='SENSOR CONTINUITY';State=if($script:Continuity -and $Continuity.GapCount -gt 0){'WATCH'}else{'OK'};Text=if($script:Continuity){'Gaps='+$Continuity.GapCount+'; coordinator gaps total '+([math]::Round($Continuity.BlindMs/1000,1))+'s. No WAN assumption.'}else{'Awaiting continuity guard.'}}
        [pscustomobject]@{Name='PROBE EXECUTION';State=if($health.Probes -eq 'OK'){'OK'}else{'WATCH'};Text=$health.Probes}
        [pscustomobject]@{Name='DEPLOYMENT';State='WATCH';Text=('Mode='+$script:DeploymentStatus+'; power guard='+$script:PowerGuard+'; Windows acceptance pending.')}
        [pscustomobject]@{Name='MTU / DF';State=$mtu.State;Text=$mtu.Text}
        [pscustomobject]@{Name='ROUTE';State=if($RouteSignature){'OK'}else{'WAITING'};Text=if($RouteSignature){$RouteSignature}else{'Independent background trace pending.'}}
        [pscustomobject]@{Name='WINDOWS TCP';State=if($TcpStatsCurrent){'OK'}elseif($FamilyAvailability.TCP_STATS -eq 'UNAVAILABLE'){'WATCH'}else{'WAITING'};Text=if($TcpStatsCurrent){'IPv4 counters active; deltas in RAM / incident TCP_Stats.csv.'}else{'TCP counters unavailable/pending; no fabricated zero samples.'}}
        [pscustomobject]@{Name='PKTMON';State=if($script:CaptureWorker){'WATCH'}elseif($PacketCaptureEnabled){'OK'}else{'OFF'};Text=if($script:CaptureWorker){'Capture worker active; status recorded in Events.log.'}elseif($PacketCaptureEnabled){'ARMED - first corroborated pretrigger starts capture.'}else{'Disabled, unavailable or not elevated.'}}
        [pscustomobject]@{Name='TRACEROUTE';State='OK';Text='Independent worker; incident requests are coalesced, not fired together.'}
        [pscustomobject]@{Name='INCIDENT CAPTURE';State=if($State.Active){'BAD'}else{'OK'};Text=('Active={0}; {1} incident(s). Sensor={2}, role={3}.' -f $State.Active,$IncidentCount,$Cfg.SENSOR_NAME,$Cfg.SENSOR_ROLE)}
    )
}
