function Invoke-Rc31SelfTest {
    $cfg=Read-MonitorConfig (Join-Path (Split-Path $PSScriptRoot -Parent) 'Monitor_Config.psd1')
    $proxy=New-TestObservation DNS_UDP Proxy Router RouterDNS FAIL DNS_TIMEOUT 10000
    $direct=@((New-TestObservation DNS_UDP A Cloudflare ExternalDNS OK NOERROR 9000),(New-TestObservation DNS_UDP B Google ExternalDNS OK NOERROR 9000))
    foreach($r in @($proxy)+$direct){$r.Data.QueryName='www.amazon.com';if($r.Status -eq 'OK'){$r.Data.Addresses=@('8.8.8.8')}}
    $a=Get-CoreAssessment (@($proxy)+$direct) 10000 $cfg;$state=New-IncidentState
    $actions=@(Update-IncidentState $state $a (@($proxy)+$direct) 10000 $cfg)
    Assert-MonitorTest ($a.Code -eq 'ROUTER_DNS_PROXY' -and $actions -contains 'PRETRIGGER') 'Matched-name proxy failure remains a capture candidate'
    foreach($r in $direct){$r.StartMonoMs=14900;$r.EndMonoMs=15000}
    $a=Get-CoreAssessment (@($proxy)+$direct) 15000 $cfg
    $actions=@(Update-IncidentState $state $a (@($proxy)+$direct) 15000 $cfg)
    Assert-MonitorTest ($actions -notcontains 'INCIDENT' -and -not $state.Active) 'Longtest regression: new direct successes cannot confirm one old proxy timeout'
    $proxy.StartMonoMs=14900;$proxy.EndMonoMs=15000
    $a=Get-CoreAssessment (@($proxy)+$direct) 15000 $cfg
    $actions=@(Update-IncidentState $state $a (@($proxy)+$direct) 15000 $cfg)
    Assert-MonitorTest ($actions -contains 'INCIDENT') 'A second advancing proxy failure confirms a persistent DNS query-path fault'
    foreach($r in $direct){$r.Data.QueryName='www.apple.com'}
    $a=Get-CoreAssessment (@($proxy)+$direct) 15000 $cfg
    Assert-MonitorTest ($a.Code -ne 'ROUTER_DNS_PROXY' -and -not $a.IncidentEligible) 'Different-name direct answers do not localize a proxy failure'
    foreach($r in $direct){$r.Data.QueryName='www.amazon.com';$r.Protocol='DNS_TCP'}
    $a=Get-CoreAssessment (@($proxy)+$direct) 15000 $cfg
    Assert-MonitorTest ($a.Code -ne 'ROUTER_DNS_PROXY') 'TCP direct answers cannot corroborate a UDP proxy comparison'
    foreach($r in $direct){$r.Protocol='DNS_UDP'}
    $tcpProxy=New-TestObservation DNS_TCP Proxy Router RouterDNS OK NOERROR 15100
    $tcpProxy.Data.QueryName='www.amazon.com';$tcpProxy.Data.Addresses=@('8.8.8.8')
    $a=Get-CoreAssessment (@($proxy,$tcpProxy)+$direct) 15100 $cfg
    Assert-MonitorTest ($a.Code -eq 'ROUTER_DNS_PROXY') 'Proxy TCP success does not erase a measured UDP-specific fault'
    $udpSuccess=New-TestObservation DNS_UDP Proxy Router RouterDNS OK NOERROR 15200
    $udpSuccess.Data.QueryName='www.cloudflare.com';$udpSuccess.Data.Addresses=@('1.1.1.1')
    $a=Get-CoreAssessment (@($proxy,$tcpProxy,$udpSuccess)+$direct) 15200 $cfg
    Assert-MonitorTest ($a.Code -ne 'ROUTER_DNS_PROXY') 'A newer usable UDP response supersedes the older proxy failure'
    $trace=Get-TraceObservation "Tracing route to 1.1.1.1`n  1     2 ms     192.168.50.1`n  2     * * * Request timed out." '1.1.1.1' $true
    Assert-MonitorTest (-not $trace.DestinationReached -and $trace.Stage -eq 'DESTINATION_UNREACHED' -and $trace.Signature -eq '192.168.50.1') 'Traceroute header is never mistaken for a reached destination'
    $trace=Get-TraceObservation "  1     2 ms     192.168.50.1`n  2     9 ms     1.1.1.1" '1.1.1.1' $true
    Assert-MonitorTest ($trace.DestinationReached -and $trace.Stage -eq 'COMPLETE') 'Numbered destination reply establishes completed trace reachability'
    $trace=Get-TraceObservation "  1     2 ms     192.168.50.1" '1.1.1.1' $false
    Assert-MonitorTest ($trace.Stage -eq 'TRACE_BUDGET') 'Killed trace remains a partial budget observation'
    $previous=[pscustomobject]@{monoMs=1000L;cpuTotalMs=100.0}
    Assert-MonitorTest ($null -eq (Get-ProcessCpuDelta 100 $null 1000)) 'Process CPU first sample is unknown, not zero'
    Assert-MonitorTest ((Get-ProcessCpuDelta 600 $previous 2000) -eq 50) 'Process CPU delta uses monotonic elapsed time'
    Assert-MonitorTest ((Get-ProcessCpuDelta 1600 $previous 2000) -eq 150) 'Multithreaded CPU may exceed one logical CPU'
    Assert-MonitorTest ($null -eq (Get-ProcessCpuDelta 90 $previous 2000) -and $null -eq (Get-ProcessCpuDelta 100 $previous 1000)) 'Reset and nonadvancing CPU samples remain unknown'
    $script:Clock=[pscustomobject]@{ElapsedMilliseconds=1000L}
    Update-ProcessResources -Reset;$sample=Get-ProcessResourceSnapshot
    Assert-MonitorTest ($sample.status -eq 'OK' -and $sample.workingSetBytes -gt 0 -and $null -eq $sample.cpuPercentOneCore) 'Actual process resources are sampled without manufacturing initial CPU'
    $sample=Get-ProcessResourceSnapshot HISTORICAL
    Assert-MonitorTest ($sample.status -eq 'UNMEASURED' -and $null -eq $sample.workingSetBytes) 'Historical replay cannot inherit the replay process RAM'
    $script:Clock.ElapsedMilliseconds=92000;$sample=Get-ProcessResourceSnapshot
    Assert-MonitorTest ($sample.status -eq 'STALE' -and $null -eq $sample.workingSetBytes) 'Frozen process resource publisher becomes unknown'
    $script:FailureStages=@{};$script:FailureStageOmitted=0L
    $row=New-TestObservation TCP443 Akamai Akamai Public FAIL DNS_FAIL
    $row.Data.DnsDetail='NO_A_ANSWER';Add-FailureStageCount $row;Add-FailureStageCount $row
    $counts=@(Get-FailureStageSummary)
    Assert-MonitorTest ($counts.Count -eq 1 -and $counts[0].count -eq 2 -and $counts[0].stage -eq 'DNS_FAIL:NO_A_ANSWER') 'Failure totals preserve the DNS detail before any TCP attempt'
    foreach($i in 1..129){$row.Name='Target'+$i;Add-FailureStageCount $row}
    Assert-MonitorTest ($script:FailureStages.Count -eq 128 -and $script:FailureStageOmitted -eq 2) 'Failure statistics are bounded and explicitly count omitted rows'
    $script:AdvisoryCounters=@{};$script:AdvisoryKeysOmitted=0L;$script:WatchActive=@{}
    $item=[pscustomobject]@{Key='PING:AdGuard';Severity='WATCH'}
    Add-AdvisoryTransition $item $true $true;Add-AdvisoryTransition $item $false;Add-AdvisoryTransition $item $true $false
    $counts=@(Get-AdvisorySummary)
    Assert-MonitorTest ($counts[0].starts -eq 2 -and $counts[0].clears -eq 1 -and $counts[0].loggedStarts -eq 1 -and $counts[0].suppressedStarts -eq 1) 'Advisory summaries distinguish observed transitions from throttled messages'
    $cfg=Read-MonitorConfig (Join-Path (Split-Path $PSScriptRoot -Parent) 'Monitor_Config.psd1');$script:Cfg=$cfg
    $script:Clock.ElapsedMilliseconds=1000;$script:NicCurrent=@{Status='OK';LinkSpeed='613 Mbps'};$script:NicMonoMs=1000L
    Assert-MonitorTest ((Get-CurrentLinkSpeed) -eq '613 Mbps') 'Latest NIC measurement supersedes startup PHY speed'
    $script:Clock.ElapsedMilliseconds=32000
    Assert-MonitorTest ($null -eq (Get-CurrentLinkSpeed)) 'Stale NIC link speed is not shown as current'
    $fixture=[MonitorDnsFixture]::new();$fixture.TruncateUdp=$true
    try{
        $result=Resolve-ProbeName '127.0.0.1' 'example.com' 700 -Port $fixture.UdpPort -TcpPort $fixture.TcpPort
        Assert-MonitorTest ($result.Status -eq 'OK' -and $result.DnsTransport -eq 'DNS_TCP_FALLBACK' -and $result.DnsFallbackReason -eq 'TRUNCATED') 'Actual truncated UDP answer falls back to a framed TCP DNS query'
        Assert-MonitorTest ($result.AnswerPolicy -eq 'PUBLIC_NAME_NONPUBLIC_ANSWER') 'TCP fallback preserves nonpublic-answer validation'
    }finally{$fixture.Dispose()}
    $fixture=[MonitorDnsFixture]::new();$fixture.TruncateUdp=$true;$fixture.TrickleTcp=$true
    try{
        $result=Resolve-ProbeName '127.0.0.1' 'example.com' 220 -Port $fixture.UdpPort -TcpPort $fixture.TcpPort
        Assert-MonitorTest ($result.Status -eq 'FAIL' -and $result.Ms -lt 650 -and $result.DnsTransport -eq 'DNS_TCP_FALLBACK') 'UDP plus TCP fallback share a bounded total resolution deadline'
    }finally{$fixture.Dispose()}
    Assert-MonitorTest ($null -eq (Get-CurlPhaseMs 0.04 0.01)) 'Nonmonotonic curl timestamps produce unknown phase latency rather than a clamped zero'
    Assert-MonitorTest ($null -eq (Get-CurlPhaseMs 0.04 0) -and $null -eq (Get-CurlPhaseMs 0 0.1 -RequireStart)) 'Uncompleted curl phase timestamps remain unknown'
    Assert-MonitorTest ((Get-CurlPhaseMs 0.01 0.04) -eq 30) 'Comparable curl timestamps preserve the measured phase duration'
    $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0);$listener.Start();$port=$listener.LocalEndpoint.Port;$listener.Stop()
    $result=Invoke-TcpProbe '127.0.0.1' $port '' 500 500
    Assert-MonitorTest ($result.Stage -eq 'TCP_ERROR' -and $result.Error.socketError -eq 'ConnectionRefused' -and $null -ne $result.Error.nativeErrorCode) 'Actual refused socket retains its native error instead of a generic TCP label'
}
