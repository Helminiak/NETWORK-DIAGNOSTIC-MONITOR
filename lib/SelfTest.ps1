function Assert-MonitorTest {
    param([bool]$Condition,[string]$Name,[string]$FailureDetails='')
    if(-not $Condition){throw ('SELF-TEST FAILED: '+$Name+$(if($FailureDetails){"`r`n"+$FailureDetails}))}
    $script:TestCount++;Write-Host ('PASS '+$Name) -ForegroundColor Green
}

function New-RefusedTcpTestSocket {
    # Reserve a loopback port WITHOUT listening. Keeping the socket bound
    # prevents another process from taking the port between setup and connect.
    $socket=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp)
    try{
        $socket.ExclusiveAddressUse=$true
        $socket.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,0))
        return $socket
    }catch{$socket.Dispose();throw}
}

function New-TestObservation {
    param([string]$Protocol,[string]$Name,[string]$Provider,[string]$Scope,[string]$Status,[string]$Stage,[long]$Time=10000)
    [pscustomobject]@{EvidenceId=[guid]::NewGuid().ToString('N');Family=switch($Protocol){DNS_UDP{'DNS'}DNS_TCP{'DNS_TRANSPORT'}default{$Protocol}};Protocol=$Protocol;Name=$Name;Provider=$Provider;Scope=$Scope;Status=$Status;Stage=$Stage;StartMonoMs=$Time-100;EndMonoMs=$Time;Data=@{TcpAttempted=($Protocol -eq 'TCP443' -and $Stage -notmatch '^DNS_')}}
}

function Invoke-MonitorSelfTest {
    $script:TestCount=0
    $root=Split-Path $PSScriptRoot -Parent
    . (Join-Path $PSScriptRoot 'Probes.ps1')
    # Parse program/developer source, not ignored machine settings, build output
    # or third-party node_modules that may use a different PowerShell version.
    $sourceFiles=@(Get-ChildItem -LiteralPath $root -File)
    foreach($folder in @('lib','verification','tools')){
        $path=Join-Path $root $folder
        if(Test-Path -LiteralPath $path){$sourceFiles+=@(Get-ChildItem -LiteralPath $path -Recurse -File)}
    }
    foreach($file in $sourceFiles | Where-Object{$_.Extension -in @('.ps1','.psd1')}){
        $tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
        Assert-MonitorTest ($errors.Count -eq 0) ('Parser: '+$file.Name)
    }
    # Deterministic continuity gap fixture: exact threshold, long gap, and
    # wall-clock adjustment MUST remain distinct from network faults.
    $ref=[datetime]::SpecifyKind([datetime]'2026-09-30T13:00:00',[System.DateTimeKind]::Utc)
    $continuity=New-ContinuityState 0 $ref
    $event=Update-ContinuityState $continuity 15000 $ref.AddSeconds(15) 15000
    Assert-MonitorTest ($null -eq $event -and $continuity.GapCount -eq 0) 'Exactly at threshold is not a sensor gap'
    $event=Update-ContinuityState $continuity 16000 $ref.AddSeconds(16) 15000
    Assert-MonitorTest ($null -eq $event) 'Normal 1-second cadence after boundary stays healthy'
    $event=Update-ContinuityState $continuity 245816000 $ref.AddSeconds(245816) 15000
    Assert-MonitorTest ($event.Type -eq 'SENSOR_GAP' -and $event.ElapsedMs -eq 245800000 -and $continuity.GapCount -eq 1 -and $continuity.BlindMs -eq 245800000) '68-hour suspension produces a single sensor gap, not network outage'
    $event=Update-ContinuityState $continuity 245817000 $ref.AddSeconds(245877) 15000
    Assert-MonitorTest ($null -eq $event -and $continuity.ClockCorrectionCount -eq 1) 'NTP/clock correction is not monitor outage'
    $cfg=Read-MonitorConfig (Join-Path $root 'Monitor_Config.psd1');$cfg.SENSOR_ROLE='BEHIND_ASUS' 
    $gateway=New-TestObservation ICMP Gateway Local Gateway OK OK
    $pings=@($gateway,(New-TestObservation ICMP P1 Cloudflare Public FAIL TimedOut),(New-TestObservation ICMP P2 Google Public FAIL TimedOut),(New-TestObservation ICMP P3 Quad9 Public FAIL TimedOut))
    $a=Get-CoreAssessment $pings 10000 $cfg
    Assert-MonitorTest ($a.Code -eq 'ICMP_ONLY_WATCH' -and -not $a.IncidentEligible -and -not $a.CaptureEligible) 'Multi-provider ICMP alone is watch, never WAN/capture'
    $dnsFail=@((New-TestObservation TCP443 C Cloudflare Public FAIL DNS_FAIL),(New-TestObservation TCP443 G Google Public FAIL DNS_TIMEOUT))
    $a=Get-CoreAssessment ($pings+$dnsFail) 10000 $cfg
    Assert-MonitorTest (-not $a.IncidentEligible) 'DNS_FAIL/DNS_TIMEOUT cannot corroborate TCP transport loss'
    $ms=New-TestObservation HTTPS Microsoft Microsoft Public FAIL TTFB_FAIL
    $a=Get-CoreAssessment ($pings+@($ms)) 10000 $cfg
    Assert-MonitorTest (-not $a.IncidentEligible) 'Microsoft-only TTFB plus ICMP is watch'
    $ms.Stage='TCP_FAIL';$a=Get-CoreAssessment ($pings+@($ms)) 10000 $cfg
    Assert-MonitorTest (-not $a.IncidentEligible) 'Microsoft-only HTTPS connect failure cannot trigger WAN'
    $tcps=@((New-TestObservation TCP443 C Cloudflare Public FAIL TCP_TIMEOUT),(New-TestObservation TCP443 G Google Public FAIL TCP_ERROR))
    $a=Get-CoreAssessment ($pings+$tcps) 10000 $cfg
    Assert-MonitorTest ($a.Code -eq 'UPSTREAM_WAN_CONFIRMED' -and $a.CaptureEligible) 'Multi-provider ICMP + actual TCP failures create corroborated pretrigger'
    $state=New-IncidentState;$actions=@(Update-IncidentState $state $a ($pings+$tcps) 10000 $cfg)
    Assert-MonitorTest ($actions -contains 'PRETRIGGER' -and $actions -notcontains 'INCIDENT') 'Capture pretrigger precedes formal debounce'
    $actions=@(Update-IncidentState $state $a ($pings+$tcps) 15000 $cfg)
    Assert-MonitorTest ($actions -notcontains 'INCIDENT') 'Elapsed dashboard cycles with reused evidence cannot confirm'
    foreach($row in $pings){$row.EndMonoMs=15000}
    $a=Get-CoreAssessment ($pings+$tcps) 15000 $cfg;$actions=@(Update-IncidentState $state $a ($pings+$tcps) 15000 $cfg)
    Assert-MonitorTest ($actions -notcontains 'INCIDENT') 'New ICMP plus stale TCP does not confirm'
    foreach($row in $tcps){$row.EndMonoMs=15000}
    $a=Get-CoreAssessment ($pings+$tcps) 15000 $cfg;$actions=@(Update-IncidentState $state $a ($pings+$tcps) 15000 $cfg)
    Assert-MonitorTest ($actions -contains 'INCIDENT' -and $state.Active -eq 'UPSTREAM_WAN_CONFIRMED') 'Independent streams advance and elapsed debounce confirms'
    $empty=Get-CoreAssessment @() 45000 $cfg;$actions=@(Update-IncidentState $state $empty @() 45000 $cfg)
    Assert-MonitorTest ($actions -notcontains 'RECOVERY' -and $state.Active) 'Missing/stale evidence never fabricates recovery'
    foreach($row in ($pings+$tcps)){$row.Status='OK';$row.Stage='OK';$row.EndMonoMs=50000}
    $healthy=Get-CoreAssessment ($pings+$tcps) 50000 $cfg
    $actions=@(Update-IncidentState $state $healthy ($pings+$tcps) 50000 $cfg)
    $actions=@(Update-IncidentState $state $healthy ($pings+$tcps) 56000 $cfg)
    Assert-MonitorTest ($actions -notcontains 'RECOVERY') 'Recovery hold also requires advancing successful observations'
    foreach($row in ($pings+$tcps)){$row.EndMonoMs=56000}
    $healthy=Get-CoreAssessment ($pings+$tcps) 56000 $cfg;$actions=@(Update-IncidentState $state $healthy ($pings+$tcps) 56000 $cfg)
    Assert-MonitorTest ($actions -contains 'RECOVERY') 'Fresh success from every implicated stream recovers'
    $proxy=New-TestObservation DNS_UDP Proxy Router RouterDNS FAIL DNS_TIMEOUT
    $goodDns=@((New-TestObservation DNS_UDP A ATT ExternalDNS OK NOERROR),(New-TestObservation DNS_UDP B Cloudflare ExternalDNS OK NOERROR))
    foreach($r in @($proxy)+$goodDns){$r.Data.QueryName='example.com';if($r.Status -eq 'OK'){$r.Data.Addresses=@('8.8.8.8')}}
    $a=Get-CoreAssessment (@($proxy)+$goodDns) 10000 $cfg
    Assert-MonitorTest ($a.Code -eq 'ROUTER_DNS_PROXY') 'ASUS DNS proxy failure isolated from clean direct resolvers'
    $proxy.Scope='BgwDNS';$a=Get-CoreAssessment (@($proxy)+$goodDns) 10000 $cfg
    Assert-MonitorTest ($a.Code -eq 'BGW_DNS_PROXY') 'BGW DNS proxy classified independently'
    $duplicate=$goodDns[1].PSObject.Copy();$duplicate.Protocol='DNS_TCP';$duplicate.Status='FAIL';$duplicate.Stage='DNS_TIMEOUT';$duplicate.EndMonoMs=9999
    $a=Get-CoreAssessment (@($proxy,$duplicate)+$goodDns) 10000 $cfg
    Assert-MonitorTest ($a.Code -eq 'BGW_DNS_PROXY') 'DNS proxy remains isolated while a separate TCP53 observation fails'
    $gateway.Status='FAIL';$gateway.Stage='TimedOut';$gateway.EndMonoMs=10000
    $tcp2=@((New-TestObservation TCP443 C Cloudflare Public FAIL TCP_TIMEOUT),(New-TestObservation TCP443 G Google Public FAIL TCP_ERROR))
    $a=Get-CoreAssessment (@($gateway)+$tcp2) 10000 $cfg
    Assert-MonitorTest ($a.Code -eq 'ROUTER_LAN') 'Behind-ASUS gateway + TCP failures localize LAN boundary'
    $cfg.SENSOR_ROLE='DIRECT_BGW';$a=Get-CoreAssessment (@($gateway)+$tcp2) 10000 $cfg
    Assert-MonitorTest ($a.Code -eq 'HOST_LOCAL_PATH') 'Direct-BGW local path failure is not automatically AT&T WAN'
    $cfg.SENSOR_ROLE='BEHIND_ASUS';$gateway.Status='OK';$gateway.EndMonoMs=10000
    $bgw=New-TestObservation ICMP BGW Local Gateway2 FAIL TimedOut
    $a=Get-CoreAssessment (@($gateway,$bgw)+$tcp2) 10000 $cfg
    Assert-MonitorTest ($a.Code -eq 'BGW_WAN_EDGE') 'Healthy ASUS + failed BGW path + TCP localizes edge boundary'
    $cfg.SENSOR_ROLE='GENERIC';$a=Get-CoreAssessment (@($gateway,$bgw)+$tcp2) 10000 $cfg
    Assert-MonitorTest ($a.Code -ne 'BGW_WAN_EDGE') 'Explicit GENERIC role prevents inferred BGW ownership'
    $stale=@((New-TestObservation ICMP P1 Cloudflare Public FAIL TimedOut 10000),(New-TestObservation ICMP P2 Google Public FAIL TimedOut 10000))
    $gateway.EndMonoMs=30000;foreach($r in $tcp2){$r.EndMonoMs=30000}
    $a=Get-CoreAssessment (@($gateway)+$stale+$tcp2) 30000 $cfg
    Assert-MonitorTest (-not $a.IncidentEligible) 'Evidence from separate time windows cannot corroborate'
    $rcodeFailures=@((New-TestObservation DNS_UDP A ATT ExternalDNS FAIL SERVFAIL 10000),(New-TestObservation DNS_UDP B Cloudflare ExternalDNS FAIL SERVFAIL 10000))
    $icmpFails=@((New-TestObservation ICMP P1 Cloudflare Public FAIL TimedOut 10000),(New-TestObservation ICMP P2 Google Public FAIL TimedOut 10000))
    $gateway.EndMonoMs=10000
    $a=Get-CoreAssessment (@($gateway)+$rcodeFailures+$icmpFails) 10000 $cfg
    Assert-MonitorTest (-not $a.IncidentEligible) 'SERVFAIL responses do not corroborate WAN transport failure'
    $wire=New-DnsQueryPacket 'example.com' 123
    [byte[]]$answer=$wire.Clone();$answer[2]=129;$answer[3]=128;$answer[7]=1
    $answer+=[byte[]]@(192,12,0,1,0,1,0,0,0,60,0,4,127,0,0,1)
    Assert-MonitorTest (Get-DnsPacketResult $answer 123 'example.com').Success 'DNS parser validates complete A response'
    Assert-MonitorTest (-not (Get-DnsPacketResult $answer 124 'example.com').Success) 'DNS transaction ID mismatch rejected'
    Assert-MonitorTest (-not (Get-DnsPacketResult $answer 123 'wrong.example').Success) 'DNS question mismatch rejected'
    [byte[]]$short=$answer[0..($wire.Length-1)]
    Assert-MonitorTest (-not (Get-DnsPacketResult $short 123 'example.com').Success) 'Header claiming an answer without RDATA rejected'
    $answer[2]=131
    Assert-MonitorTest ((Get-DnsPacketResult $answer 123 'example.com').RCode -eq 'TRUNCATED') 'Truncated UDP response is not falsely successful'
    $answer[2]=1
    Assert-MonitorTest (-not (Get-DnsPacketResult $answer 123 'example.com').Success) 'DNS query masquerading as response rejected'
    # Real loopback wire tests: fragmented TCP frame, dropped UDP, trickle TCP deadline.
    if(-not ('MonitorDnsFixture' -as [type])){
        Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
public sealed class MonitorDnsFixture : IDisposable {
    public int UdpPort, TcpPort;
    public bool DropUdp, TrickleTcp, CloseTcp, TruncateUdp;
    UdpClient udp; TcpListener tcp; volatile bool stop;
    public MonitorDnsFixture() {
        udp=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        UdpPort=((IPEndPoint)udp.Client.LocalEndPoint).Port;
        tcp=new TcpListener(IPAddress.Loopback,0);tcp.Start();
        TcpPort=((IPEndPoint)tcp.LocalEndpoint).Port;
        Task.Run((Action)UdpLoop);Task.Run((Action)TcpLoop);
    }
    byte[] Response(byte[] q) {
        byte[] b=new byte[q.Length+16];Array.Copy(q,b,q.Length);
        b[2]=129;b[3]=128;b[6]=0;b[7]=1;
        byte[] a={192,12,0,1,0,1,0,0,0,60,0,4,127,0,0,1};
        Array.Copy(a,0,b,q.Length,16);return b;
    }
    void UdpLoop() { while(!stop) { try {
        IPEndPoint peer=new IPEndPoint(IPAddress.Any,0);byte[] q=udp.Receive(ref peer);
        if(!DropUdp){byte[] b=Response(q);if(TruncateUdp)b[2]|=2;udp.Send(b,b.Length,peer);}
    } catch { if(stop)return; } } }
    byte[] Exact(NetworkStream s,int count) {
        byte[] b=new byte[count];int offset=0;
        while(offset<count){int n=s.Read(b,offset,count-offset);if(n==0)throw new Exception();offset+=n;}return b;
    }
    void TcpLoop() { while(!stop) { try { using(TcpClient c=tcp.AcceptTcpClient()) {
        NetworkStream s=c.GetStream();s.ReadTimeout=1000;
        byte[] prefix=Exact(s,2);byte[] q=Exact(s,(prefix[0]<<8)|prefix[1]);
        if(CloseTcp)continue;
        byte[] b=Response(q);byte[] p={(byte)(b.Length>>8),(byte)(b.Length&255)};
        s.Write(p,0,1);Thread.Sleep(20);s.Write(p,1,1);
        if(TrickleTcp){for(int i=0;i<b.Length;i++){s.Write(b,i,1);Thread.Sleep(40);}}
        else {s.Write(b,0,5);Thread.Sleep(20);s.Write(b,5,b.Length-5);}
    }} catch { if(stop)return; } } }
    public void Dispose(){stop=true;udp.Close();tcp.Stop();}
}
'@
    }
    $fixture=[MonitorDnsFixture]::new()
    try{
        $result=Invoke-DnsQuery '127.0.0.1' 'example.com' 700 -Port $fixture.UdpPort
        Assert-MonitorTest ($result.Status -eq 'OK' -and $result.Addresses[0] -eq '127.0.0.1') 'Real direct UDP query/response'
        $result=Invoke-DnsQuery '127.0.0.1' 'example.com' 700 -Tcp -Port $fixture.TcpPort
        Assert-MonitorTest ($result.Status -eq 'OK') 'Real DNS-over-TCP length framing and fragmented response'
        $fixture.DropUdp=$true
        $result=Invoke-DnsQuery '127.0.0.1' 'example.com' 220 -Port $fixture.UdpPort
        Assert-MonitorTest ($result.Status -eq 'FAIL' -and $result.Stage -eq 'DNS_TIMEOUT' -and $result.Ms -ge 180 -and $result.Ms -lt 650) 'Configured UDP timeout enforced'
        $fixture.TrickleTcp=$true
        $result=Invoke-DnsQuery '127.0.0.1' 'example.com' 220 -Tcp -Port $fixture.TcpPort
        Assert-MonitorTest ($result.Status -eq 'FAIL' -and $result.Ms -lt 650) 'TCP total deadline survives a trickling response'
    }finally{$fixture.Dispose()}
    $fixture=[MonitorDnsFixture]::new();$fixture.CloseTcp=$true
    try{$result=Invoke-DnsQuery '127.0.0.1' 'example.com' 700 -Tcp -Port $fixture.TcpPort;Assert-MonitorTest ($result.Status -eq 'FAIL' -and $result.Ms -lt 650) 'Premature DNS TCP EOF rejected'}finally{$fixture.Dispose()}
    $closed=New-RefusedTcpTestSocket;$closedPort=$closed.LocalEndPoint.Port
    try{
        $result=Invoke-TcpProbe '127.0.0.1' $closedPort '127.0.0.1' 200 300
        Assert-MonitorTest ($result.TcpAttempted -and $result.Stage -in @('TCP_ERROR','TCP_TIMEOUT')) 'Closed TCP port is a connect failure with DNS bypassed' -FailureDetails ($result | ConvertTo-Json -Depth 6 -Compress)
    }finally{$closed.Dispose()}
    $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0);$listener.Start()
    try{$result=Invoke-TcpProbe '127.0.0.1' $listener.LocalEndpoint.Port '127.0.0.1' 200 700;Assert-MonitorTest ($result.TcpAttempted -and $result.Status -eq 'OK') 'Loopback TCP listener confirms a real successful connect'}finally{$listener.Stop()}
    $result=Invoke-TcpProbe 'example.com' $closedPort '127.0.0.1' 200 300
    Assert-MonitorTest (-not $result.TcpAttempted -and $result.Stage -in @('DNS_FAIL','DNS_TIMEOUT') -and $null -eq $result.Ms) 'DNS failure returns zero TCP attempts and no connect latency'
    $cfg=Read-MonitorConfig (Join-Path $root 'Monitor_Config.psd1')
    $clock=[Diagnostics.Stopwatch]::StartNew();$queue=[Collections.Concurrent.ConcurrentQueue[object]]::new()
    $scheduler=New-ProbeScheduler $cfg (Join-Path $PSScriptRoot 'Probes.ps1') @{} $queue $clock
    foreach($job in $scheduler.Jobs.Values){$job.Enabled=$job.Name -in @('ICMP','DNS');$job.IntervalMs=300;$job.NextMs=if($job.Name -eq 'ICMP'){0}else{75}}
    $scheduler.WorkerScript=@'
param($Path,$Config,$Context,$Queue,$Clock,$Family,$Sweep,$Name)
$Queue.Enqueue([pscustomobject]@{Family=$Family;Stage='START';Time=$Clock.ElapsedMilliseconds})
if($Family -eq 'DNS'){Start-Sleep -Milliseconds 950}else{Start-Sleep -Milliseconds 35}
$Queue.Enqueue([pscustomobject]@{Family=$Family;Stage='END';Time=$Clock.ElapsedMilliseconds})
'@
    try{
        while($clock.ElapsedMilliseconds -lt 1500){Step-ProbeScheduler $scheduler;Start-Sleep -Milliseconds 10}
        $items=New-Object System.Collections.ArrayList;$row=$null;while($queue.TryDequeue([ref]$row)){[void]$items.Add($row);$row=$null}
        $dnsStart=($items | Where-Object{$_.Family -eq 'DNS' -and $_.Stage -eq 'START'} | Select-Object -First 1).Time
        $dnsEnd=($items | Where-Object{$_.Family -eq 'DNS' -and $_.Stage -eq 'END'} | Select-Object -First 1).Time
        Assert-MonitorTest (@($items | Where-Object{$_.Family -eq 'ICMP' -and $_.Stage -eq 'END' -and $_.Time -gt $dnsStart -and $_.Time -lt $dnsEnd}).Count -ge 1) 'Slow DNS worker does not block independent ICMP worker'
        Assert-MonitorTest ($scheduler.Jobs.DNS.Skipped -ge 1 -and $scheduler.Jobs.DNS.Sequence -le 2) 'Busy family skips deadlines; no overlapping sweeps/catch-up burst'
    }finally{Stop-ProbeScheduler $scheduler}
    $testClock=[pscustomobject]@{ElapsedMilliseconds=0L}
    $testScheduler=New-ProbeScheduler $cfg (Join-Path $PSScriptRoot 'Probes.ps1') @{} ([Collections.Concurrent.ConcurrentQueue[object]]::new()) $testClock
    foreach($job in $testScheduler.Jobs.Values){$job.Enabled=($job.Name -eq 'ICMP')}
    $testScheduler.WorkerScript="param(`$a,`$b,`$c,`$d,`$e,`$f,`$g,`$h)"
    try{
        Step-ProbeScheduler $testScheduler
        $deadline=[datetime]::UtcNow.AddSeconds(3)
        while($testScheduler.Jobs.ICMP.Handle -and -not $testScheduler.Jobs.ICMP.Handle.IsCompleted -and [datetime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 20}
        Assert-MonitorTest ($testScheduler.Jobs.ICMP.Handle.IsCompleted) 'Scheduler fixture worker completed before simulated suspension'
        $testClock.ElapsedMilliseconds=245800000L
        Step-ProbeScheduler $testScheduler
        Assert-MonitorTest ($testScheduler.Jobs.ICMP.DeadlineSlots -eq $testScheduler.Jobs.ICMP.ScheduledStarts+$testScheduler.Jobs.ICMP.Skipped) 'Scheduled deadline slots equal scheduled launches plus skips after a 68-hour pause'
        Assert-MonitorTest ($testScheduler.Jobs.ICMP.Skipped -ge 49159 -and $testScheduler.Jobs.ICMP.Sequence -le 2) 'Idle scheduler accounts for missed slots after 68-hour pause without replaying them'
    }finally{Stop-ProbeScheduler $testScheduler}
    $requestClock=[pscustomobject]@{ElapsedMilliseconds=0L}
    $requestScheduler=New-ProbeScheduler $cfg (Join-Path $PSScriptRoot 'Probes.ps1') @{} ([Collections.Concurrent.ConcurrentQueue[object]]::new()) $requestClock
    foreach($job in $requestScheduler.Jobs.Values){$job.Enabled=($job.Name -eq 'TRACE')}
    $requestScheduler.WorkerScript="param(`$a,`$b,`$c,`$d,`$e,`$f,`$g,`$h);Start-Sleep -Seconds 5"
    $requestScheduler.Jobs.TRACE.Requested=$true
    Step-ProbeScheduler $requestScheduler
    Assert-MonitorTest ($requestScheduler.Jobs.TRACE.RequestedStarts -eq 1 -and $requestScheduler.Jobs.TRACE.DeadlineSlots -eq 0 -and $requestScheduler.Jobs.TRACE.ScheduledStarts -eq 0) 'Requested traceroute is accounted separately from fixed-rate deadline slots'
    Stop-ProbeScheduler $requestScheduler
    Assert-MonitorTest ($requestScheduler.Jobs.TRACE.Sequence -eq $requestScheduler.Jobs.TRACE.Completed+$requestScheduler.Jobs.TRACE.Aborted+$requestScheduler.Jobs.TRACE.Failed -and $requestScheduler.Jobs.TRACE.Aborted -eq 1) 'Interrupted worker is counted as aborted rather than completed during shutdown'
    # Actual ICMP worker timestamps establish launch spacing; cap is also inspected statically.
    $script:Cfg=$cfg;$script:Clock=[Diagnostics.Stopwatch]::StartNew();$script:Queue=[Collections.Concurrent.ConcurrentQueue[object]]::new()
    $script:Ctx=@{Targets=@(1..8 | ForEach-Object{@{Name="Loop$_";IP='127.0.0.1';Provider='Loop';Role='Public'}})}
    $script:Family='ICMP';$script:SweepId='TEST';Invoke-IcmpFamily
    $starts=@();$row=$null;while($Queue.TryDequeue([ref]$row)){$starts+=$row.StartMonoMs;$row=$null};$spacing=$true
    for($i=1;$i -lt $starts.Count;$i++){if($starts[$i]-$starts[$i-1] -lt $cfg.PingStaggerMs){$spacing=$false}}
    Assert-MonitorTest ($starts.Count -eq 8 -and $spacing) 'Eight loopback ICMP probes preserve 75 ms deterministic launch staggering'
    $tempDir=Join-Path ([IO.Path]::GetTempPath()) ('NetDiagSelfTest_'+[guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($tempDir)
    try{
        $path=Join-Path $tempDir 'Summary_Live.txt';Write-AtomicText $path 'first';Write-AtomicText $path 'second'
        Assert-MonitorTest (([IO.File]::ReadAllText($path)) -eq 'second' -and @(Get-ChildItem $tempDir -Filter '*.tmp').Count -eq 0) 'Summary atomically replaces complete previous content'
    }finally{[IO.File]::Delete($path);[IO.Directory]::Delete($tempDir)}
    $script:Cfg=$cfg;$script:RouteInfo=[pscustomobject]@{AdapterName='Test Ethernet';LinkSpeed='1 Gbps';Gateway='192.168.50.1';SystemDns='192.168.50.1'}
    $script:Targets=@([pscustomobject]@{Name='Default-Gateway';IP=$RouteInfo.Gateway;Provider='Local';Role='Gateway'})+@($cfg.PublicTargets)
    $script:AllDnsResolvers=@($cfg.DnsResolvers);$script:HttpsSites=$cfg.HttpsSites;$script:TcpConnectTargets=$cfg.TcpConnectTargets;$script:DnsTransportResolvers=$cfg.DnsTransportResolvers
    $script:RunDir='SelfTest';$script:TopologyMode='GENERIC_ROUTER';$script:PacketCaptureEnabled=$false;$script:IsAdministrator=$false;$script:PktMonExe=$null;$script:CurlExe='curl.exe'
    Initialize-DisplayState;$script:State=New-IncidentState;$assessment=New-Assessment 'HEALTHY' 'OK' 'Self-test frame.'
    $frame=@(Render-Dashboard $assessment ([datetime]::Now) '-' @() @() -FrameOnly)
    $sections=@('PING / ROUTING','DNS RESOLVERS','HTTPS TRANSACTION','TCP / 443','DNS TRANSPORT','LOCAL STACK','BACKGROUND FORENSICS','CURRENT NETWORK WATCHLIST','RECENT NETWORK HISTORY')
    $last=-1;$ordered=$true
    foreach($section in $sections){$found=-1;for($i=0;$i -lt $frame.Count;$i++){if($frame[$i].Text -like ('*'+$section+'*')){$found=$i;break}};if($found -le $last){$ordered=$false};$last=$found}
    Assert-MonitorTest $ordered 'Dashboard preserves baseline sections and their order'
    $watch=@(1..8 | ForEach-Object{[pscustomobject]@{Severity='WATCH';Text=('Watch '+$_)}})
    $changed=@(Render-Dashboard $assessment ([datetime]::Now) '-' $watch @() -FrameOnly)
    Assert-MonitorTest ($changed.Count -eq $frame.Count) 'Watchlist updates preserve fixed dashboard row count'
    Assert-MonitorTest (@($frame | Where-Object{$_.Text -like '*LAST CONFIRMED INCIDENT: NONE since program start*'}).Count -eq 1) 'Top label distinguishes run-wide confirmed incidents from individual failed probes'
    $transportIndex=-1
    for($i=0;$i -lt $frame.Count;$i++){if($frame[$i].Text -like '*DNS TRANSPORT (*'){$transportIndex=$i+3;break}}
    $resolver=$script:DnsTransportResolvers[0].Name
    foreach($case in @(
        @{UDP='-';TCP='-';DoH='N/A';Color='DarkGray';Name='Unmeasured DNS transports remain gray'},
        @{UDP='OK';TCP='OK';DoH='N/A';Color='Green';Name='Successful UDP/TCP stay green when DoH is not configured'},
        @{UDP='FAIL';TCP='OK';DoH='N/A';Color='Red';Name='UDP failure stays red despite unconfigured DoH'},
        @{UDP='OK';TCP='FAIL';DoH='N/A';Color='Red';Name='TCP53 failure stays red despite unconfigured DoH'},
        @{UDP='FAIL';TCP='-';DoH='N/A';Color='Red';Name='DNS transport failure remains visible while another test is pending'},
        @{UDP='OK';TCP='OK';DoH='FAIL';Color='Red';Name='Configured DoH endpoint failure remains visible'},
        @{UDP='OK';TCP='OK';DoH='OK';Color='Green';Name='Successful configured DNS transports remain green'}
    )){
        $script:DnsTransportStats[$resolver].LastUDP=$case.UDP;$script:DnsTransportStats[$resolver].LastTCP53=$case.TCP;$script:DnsTransportStats[$resolver].LastDoH=$case.DoH
        $colorFrame=@(Render-Dashboard $assessment ([datetime]::Now) '-' @() @() -FrameOnly)
        Assert-MonitorTest ($transportIndex -ge 0 -and $colorFrame[$transportIndex].Text -like ('*'+$resolver+'*') -and $colorFrame[$transportIndex].Color -eq $case.Color -and $colorFrame.Count -eq $frame.Count) $case.Name
    }
    . (Join-Path $PSScriptRoot 'Rc3SelfTest.ps1');Invoke-Rc3SelfTest
    Invoke-HardeningSelfTest
    Invoke-StorageSelfTest
    Invoke-NotificationSelfTest
    . (Join-Path $PSScriptRoot 'Rc31SelfTest.ps1');Invoke-Rc31SelfTest
    Write-Host ('SELF-TEST PASSED: '+$script:TestCount+' checks. No external network or packet capture used.') -ForegroundColor Cyan
}

function Invoke-NotificationSelfTest {
    $temp=Join-Path ([IO.Path]::GetTempPath()) ('NetDiagAlertSelfTest_'+[guid]::NewGuid().ToString('N'))
    $script:Cfg=Read-MonitorConfig (Join-Path (Split-Path $PSScriptRoot -Parent) 'Monitor_Config.psd1')
    $script:Cfg.RootDir=$temp;$script:Cfg.SENSOR_NAME='AlertFixture';$script:Cfg.SENSOR_ROLE='BEHIND_ASUS'
    $script:RunDir=$null;$script:RunId='ALERT-TEST';$script:Clock=[pscustomobject]@{ElapsedMilliseconds=0L}
    $script:State=New-IncidentState;$script:Cfg.CompressClosedIncidents=$false
    $Cfg=$script:Cfg;$Clock=$script:Clock;$State=$script:State
    $token='T'*30;$userKey='U'*30
    $protected=[pscustomobject]@{AppToken=(ConvertTo-SecureString $token -AsPlainText -Force);UserKey=(ConvertTo-SecureString $userKey -AsPlainText -Force)}
    $success='param($Path,$Item,$Secrets,$Device,$Timeout); Start-Sleep -Milliseconds 350; @{Succeeded=$true;Retryable=$false;StatusCode=200;FailureCode="";RetryAfterSec=0}'
    $retry='param($Path,$Item,$Secrets,$Device,$Timeout); @{Succeeded=$false;Retryable=$true;StatusCode=0;FailureCode="TIMEOUT";RetryAfterSec=0}'
    $reject='param($Path,$Item,$Secrets,$Device,$Timeout); @{Succeeded=$false;Retryable=$false;StatusCode=400;FailureCode="HTTP_400";RetryAfterSec=0}'
    $incident=New-Assessment 'UPSTREAM_WAN_CONFIRMED' 'BAD' 'Corroborated fixture' @((New-TestObservation ICMP C Cloudflare Public FAIL TimedOut),(New-TestObservation TCP443 G Google Public FAIL TCP_TIMEOUT)) $true $true
    function Reset-AlertFixture {
        Initialize-Notifications -SkipCredentials
        $script:Alerts.Ready=$true;$script:Alerts.Mode='ARMED';$script:Alerts.Secrets=$protected;$script:Alerts.TransportScript=$success
        $script:Alerts.StatePath=Join-Path $script:SensorRoot 'Alert_State.json'
        $script:Cfg.AlertMaxPending=24;$script:Cfg.AlertMaxPerHour=12;$script:Cfg.AlertOnRecovery=$true
        $script:State.EpisodeId=[guid]::NewGuid().ToString('N')
    }
    function Wait-AlertFixture {
        $limit=[Diagnostics.Stopwatch]::StartNew()
        while($script:Alerts.Worker -and $limit.Elapsed.TotalSeconds -lt 5){Step-Notifications;Start-Sleep -Milliseconds 10}
        if($script:Alerts.Worker){throw 'Notification fixture worker deadline exceeded.'}
    }
    function Release-AlertHold {
        $script:Alerts.Episode.StartedUTC=[datetime]::UtcNow.AddSeconds(-20)
        $script:Alerts.Pending[0].NextAttemptUTC=[datetime]::UtcNow.AddSeconds(-1).ToString('o')
    }
    try{
        Initialize-Storage
        Initialize-Notifications -SkipCredentials
        Assert-MonitorTest ($script:Alerts.Mode -eq 'NOT_CONFIGURED' -and -not $script:Alerts.Ready) 'Missing credentials leave probes running without network delivery'
        Assert-MonitorTest (Test-PushoverKeys $protected) 'Protected Pushover keys validate without printing their values'
        $keyPath=Join-Path $temp 'private\keys.clixml';[void][IO.Directory]::CreateDirectory((Split-Path $keyPath -Parent))
        $protected | Export-Clixml -LiteralPath $keyPath -Encoding UTF8
        $saved=[IO.File]::ReadAllText($keyPath);$loaded=Import-Clixml -LiteralPath $keyPath
        if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){Assert-MonitorTest ($saved -notmatch $token -and $saved -notmatch $userKey -and (Test-PushoverKeys $loaded)) 'Windows DPAPI keys round-trip without plaintext secrets on disk'}else{Write-Host 'SKIP Windows DPAPI encryption: portable fixture only (no production secrets).'}
        $guard=$false;try{Assert-PushoverSecretLocation $keyPath $temp (Split-Path $PSScriptRoot -Parent)}catch{$guard=$true}
        Assert-MonitorTest $guard 'Credential location guard keeps keys outside managed logs and release exports'
        Reset-AlertFixture
        foreach($type in @('WATCH_START','PRETRIGGER','ASSESSMENT_CHANGE','RECLASSIFY')){Receive-NotificationEvent $type 'Microsoft TTFB / ICMP warning' $incident}
        $watch=New-Assessment 'ICMP_ONLY_WATCH' 'WATCH' 'Informational echo loss'
        Receive-NotificationEvent 'INCIDENT' 'Uncorroborated' $watch
        Assert-MonitorTest ($script:Alerts.Pending.Count -eq 0) 'ICMP-only, Microsoft-only, watches and pretriggers do not page'
        Receive-NotificationEvent 'INCIDENT' 'Confirmed outage' $incident
        Receive-NotificationEvent 'INCIDENT' 'Continuing reclassified outage' $incident
        Step-Notifications
        Assert-MonitorTest ($script:Alerts.Pending.Count -eq 1 -and -not $script:Alerts.Worker) 'One incident alert waits for the configured persistence hold'
        Release-AlertHold
        $timer=[Diagnostics.Stopwatch]::StartNew();Step-Notifications;$timer.Stop()
        Assert-MonitorTest ($script:Alerts.Worker -and $timer.ElapsedMilliseconds -lt 300) 'Notification delivery starts asynchronously without waiting for the slow transport'
        Wait-AlertFixture
        Assert-MonitorTest ($script:Alerts.Delivered -eq 1 -and $script:Alerts.Pending.Count -eq 0 -and $script:Alerts.Episode.Sent) 'Accepted onset is recorded once and removed from the outbox'
        Receive-NotificationEvent 'RECOVERY' 'Fresh probes recovered'
        Receive-NotificationEvent 'RECOVERY' 'Repeated display update'
        Assert-MonitorTest ($script:Alerts.Pending.Count -eq 1 -and $script:Alerts.Pending[0].Type -eq 'RECOVERY' -and $script:Alerts.Pending[0].Priority -eq -1) 'One quiet recovery follows an accepted onset'
        Step-Notifications
        Assert-MonitorTest (-not $script:Alerts.Worker) 'Global cooldown prevents rapid incident/recovery notification bursts'
        $script:Alerts.SentTimes.Clear();Step-Notifications;Wait-AlertFixture
        Assert-MonitorTest ($script:Alerts.Delivered -eq 2 -and $script:Alerts.Pending.Count -eq 0) 'Recovery is delivered once after cooldown allows it'
        Reset-AlertFixture
        Receive-NotificationEvent 'INCIDENT' 'Short fault' $incident;Receive-NotificationEvent 'RECOVERY' 'Short fault cleared'
        Assert-MonitorTest ($script:Alerts.Pending.Count -eq 0 -and -not $script:Alerts.Episode -and $script:Alerts.Delivered -eq 0) 'Brief confirmed fault cancels its held push while local recording is preserved'
        Reset-AlertFixture;$script:Alerts.TransportScript=$retry
        Receive-NotificationEvent 'INCIDENT' 'Offline outage' $incident;Release-AlertHold;Step-Notifications;Wait-AlertFixture
        Assert-MonitorTest ($script:Alerts.Pending.Count -eq 1 -and $script:Alerts.Failed -eq 1 -and $script:Alerts.Mode -eq 'DEFERRED' -and (Convert-MonitorUtc $script:Alerts.Pending[0].NextAttemptUTC) -gt [datetime]::UtcNow.AddSeconds(20)) 'Transport failure keeps bounded outbox state with retry backoff'
        Receive-NotificationEvent 'RECOVERY' 'Connection returned'
        Assert-MonitorTest ($script:Alerts.Pending[0].Type -eq 'INCIDENT_RECOVERED' -and $script:Alerts.Pending[0].Message -like '*Recovered UTC=*') 'Outage recovered before delivery becomes one combined historical notification'
        $script:Alerts.TransportScript=$success;Step-Notifications;Wait-AlertFixture
        Assert-MonitorTest ($script:Alerts.Delivered -eq 1 -and $script:Alerts.Pending.Count -eq 0) 'Combined delayed incident/recovery sends without a duplicate recovery'
        Reset-AlertFixture;$script:Alerts.TransportScript='param($Path,$Item,$Secrets,$Device,$Timeout); @{Succeeded=$false;Retryable=$true;StatusCode=429;FailureCode="HTTP_429";RetryAfterSec=900}'
        [void](Add-Notification 'STORAGE_WARNING' 'QUOTA' 'Service quota fixture');Step-Notifications;Wait-AlertFixture
        Assert-MonitorTest ($script:Alerts.Ready -and $script:Alerts.Pending.Count -eq 1 -and (Convert-MonitorUtc $script:Alerts.Pending[0].NextAttemptUTC) -gt [datetime]::UtcNow.AddSeconds(890)) 'Service quota response defers retries for the advertised delay'
        Reset-AlertFixture;$script:Cfg.AlertShutdownWaitSec=0
        [void](Add-Notification 'FATAL' 'STOP' 'Shutdown fixture');$timer=[Diagnostics.Stopwatch]::StartNew();Stop-Notifications;$timer.Stop()
        Assert-MonitorTest ($timer.ElapsedMilliseconds -lt 300 -and $script:Alerts.Worker -and (Get-Content -LiteralPath $script:Alerts.StatePath -Raw | ConvertFrom-Json).Pending.Count -eq 1) 'Bounded shutdown retains an in-flight notification for restart'
        Wait-AlertFixture;$script:Cfg.AlertShutdownWaitSec=5
        Reset-AlertFixture
        Receive-NotificationEvent 'INCIDENT' 'First outage' $incident;Release-AlertHold;Step-Notifications
        $oldId=$script:State.EpisodeId;Receive-NotificationEvent 'RECOVERY' 'First outage recovered'
        $script:State.EpisodeId=[guid]::NewGuid().ToString('N');$newId=$script:State.EpisodeId
        Receive-NotificationEvent 'INCIDENT' 'Second outage' $incident;Wait-AlertFixture
        Assert-MonitorTest ($script:Alerts.Episode.Id -eq $newId -and @($script:Alerts.Pending | Where-Object{$_.EpisodeId -eq $oldId -and $_.Type -eq 'RECOVERY'}).Count -eq 1 -and @($script:Alerts.Pending | Where-Object{$_.EpisodeId -eq $newId -and $_.Type -eq 'INCIDENT'}).Count -eq 1) 'Recovery during in-flight delivery preserves both old recovery and a new incident'
        Reset-AlertFixture
        Receive-NotificationEvent 'STORAGE_WARNING' 'Compression failed';Receive-NotificationEvent 'STORAGE_WARNING' 'Compression failed again'
        Assert-MonitorTest ($script:Alerts.Pending.Count -eq 1) 'Repeated storage degradation is suppressed for the fault cooldown'
        Reset-AlertFixture
        Receive-NotificationEvent 'SENSOR_GAP' 'Coordinator missed scheduled execution'
        Receive-NotificationEvent 'SENSOR_GAP' 'Coordinator missed scheduled execution again'
        Assert-MonitorTest ($script:Alerts.Pending.Count -eq 1 -and $script:Alerts.Pending[0].Type -eq 'SENSOR_GAP') 'A sensor gap alerts once and is rate-limited independently of WAN incidents'
        Reset-AlertFixture

        $script:Cfg.AlertMaxPending=3
        [void](Add-Notification 'CAPTURE_FAILED' 'A' 'Capture unavailable');[void](Add-Notification 'RECORDER_LIMIT' 'B' 'Recording capped');[void](Add-Notification 'CAPTURE_FAILED' 'C' 'Queue full')
        [void](Add-Notification 'STORAGE_WARNING' 'OVERFLOW' 'Nonfatal rejected at queue capacity')
        [void](Add-Notification 'FATAL' 'D' 'Monitor stopped')
        Assert-MonitorTest ($script:Alerts.Pending.Count -eq 3 -and @($script:Alerts.Pending | Where-Object{$_.Type -eq 'FATAL'}).Count -eq 1 -and $script:Alerts.Dropped -eq 2) 'Bounded queue admits fatal alerts by evicting an older nonfatal item'
        Save-NotificationState
        $stateText=[IO.File]::ReadAllText($script:Alerts.StatePath)
        Assert-MonitorTest ($stateText -notmatch $token -and $stateText -notmatch $userKey -and [Text.Encoding]::UTF8.GetByteCount($stateText) -le 256KB) 'Bounded persistent outbox contains identity and payloads without credentials'
        $payloadItem=$script:Alerts.Pending[0];$payloadItem.Message='A & B + C';$payloadItem.CreatedUTC='1970-01-01T00:00:01Z'
        $encoded=Get-PushoverEncodedPayload $payloadItem $protected 'my_phone'
        Assert-MonitorTest ($encoded -match 'message=A%20%26%20B%20%2B%20C' -and $encoded -match 'timestamp=1(&|$)' -and $encoded -match 'device=my_phone') 'Pushover API form escapes payloads and includes original UTC timestamp/device'
        $expected=@($script:Alerts.Pending | ForEach-Object{$_.Id});$script:Alerts.SentTimes.Add([datetime]::UtcNow);Save-NotificationState
        Initialize-Notifications -SkipCredentials;$script:Alerts.Ready=$true;Connect-NotificationStorage
        Assert-MonitorTest ($script:Alerts.Pending.Count -eq 3 -and $script:Alerts.Pending[0].Id -eq $expected[0] -and $script:Alerts.SentTimes.Count -eq 1 -and -not $script:Alerts.Episode) 'Restart restores pending IDs/rate budget without inventing prior recovery'
        foreach($item in $script:Alerts.Pending){$item.ExpiresUTC=[datetime]::UtcNow.AddSeconds(-1).ToString('o')};Step-Notifications
        Assert-MonitorTest ($script:Alerts.Pending.Count -eq 0 -and $script:Alerts.Dropped -eq 3) 'Expired notifications are removed instead of retried indefinitely'
        Reset-AlertFixture;$script:Cfg.AlertMaxPerHour=1;$script:Alerts.SentTimes.Add([datetime]::UtcNow.AddMinutes(-2))
        [void](Add-Notification 'FATAL' 'LIMIT' 'Held by hourly limit');Step-Notifications
        Assert-MonitorTest ($script:Alerts.Mode -eq 'RATE_LIMITED' -and -not $script:Alerts.Worker -and $script:Alerts.Pending.Count -eq 1) 'Hourly accepted-message cap prevents excessive notifications'
        Reset-AlertFixture;$script:Alerts.TransportScript=$reject
        [void](Add-Notification 'FATAL' 'REJECT' 'Invalid service setup');Step-Notifications;Wait-AlertFixture
        Assert-MonitorTest ($script:Alerts.Mode -eq 'CONFIG_ERROR' -and -not $script:Alerts.Ready -and $script:Alerts.Pending.Count -eq 1) 'Permanent API rejection retains pending alerts and exposes configuration error'
        [void](Write-ManagedText $script:Alerts.StatePath '{bad-json' -Critical -Final)
        Initialize-Notifications -SkipCredentials;$script:Alerts.Ready=$true;Connect-NotificationStorage;Stop-Notifications
        Assert-MonitorTest ($script:Alerts.Mode -eq 'STATE_ERROR' -and -not $script:Alerts.StateWritable -and [IO.File]::ReadAllText($script:Alerts.StatePath) -eq '{bad-json') 'Unreadable outbox is exposed and preserved instead of overwritten on shutdown'
        Update-StorageUsage
        $actual=[long](Get-ChildItem -LiteralPath $script:SensorRoot -Recurse -File -Force | Where-Object{$_.Name -ne '.sensor.lock'} | Measure-Object Length -Sum).Sum
        Assert-MonitorTest ($script:Storage.Used -eq $actual -and $script:Storage.Used -le $script:Storage.Quota) 'Persistent alert state participates in sensor storage accounting/quota'
        $script:Cfg.PushoverSecretPath=Join-Path $temp 'private\missing.clixml';Initialize-Notifications
        Assert-MonitorTest (-not $script:Alerts.Ready -and $script:Alerts.Mode -eq 'CONFIG_ERROR') 'Unsafe custom key path is rejected before any credential read'
    }finally{
        if($script:Alerts -and $script:Alerts.Worker){$script:Alerts.Worker.PowerShell.Stop();$script:Alerts.Worker.PowerShell.Dispose()}
        if($script:StorageLock){$script:StorageLock.Dispose();$script:StorageLock=$null}
        $full=[IO.Path]::GetFullPath($temp);$allowed=(Join-Path ([IO.Path]::GetFullPath([IO.Path]::GetTempPath())) 'NetDiagAlertSelfTest_')
        if($full.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase) -and [IO.Directory]::Exists($full)){Remove-Item -LiteralPath $full -Recurse -Force}
        $script:RunDir=$null;$script:Storage=$null;$script:Alerts=$null;$script:LogPaths=@{};$script:Writers=@{}
    }
}

function Invoke-StorageSelfTest {
    $temp=Join-Path ([IO.Path]::GetTempPath()) ('NetDiagStorageSelfTest_'+[guid]::NewGuid().ToString('N'))
    $script:Cfg=Read-MonitorConfig (Join-Path (Split-Path $PSScriptRoot -Parent) 'Monitor_Config.psd1')
    $Cfg=$script:Cfg
    $Cfg.RootDir=$temp;$Cfg.SENSOR_NAME='Fixture';$Cfg.CompressAfterHours=0;$Cfg.CompressClosedIncidents=$false
    $script:RunDir=$null;$script:Clock=[pscustomobject]@{ElapsedMilliseconds=0L};$script:RunId='STORAGE-TEST';$script:LogPaths=@{};$script:EvidenceWorker=$null
    $Clock=$script:Clock
    try{
        Initialize-Storage
        $script:RunDir=Join-Path $SensorRoot 'Run_fixture'
        $script:IncidentRoot=Join-Path $RunDir 'Incidents';$script:PacketDir=Join-Path $RunDir 'PacketCaptures'
        foreach($dir in @($RunDir,$IncidentRoot,$PacketDir)){[void][IO.Directory]::CreateDirectory($dir)}
        Open-RunLogs;$script:RecentHistory=New-Object Collections.ArrayList
        $script:State=New-IncidentState;$State.EpisodeId='episode-1';$script:Assessment=New-Assessment 'TEST_INCIDENT' 'BAD' 'Storage fixture'
        $State=$script:State;$State.EpisodeId='episode-1';$Assessment=$script:Assessment
        $record=[pscustomobject][ordered]@{SchemaVersion=1;TimestampUTC=[datetime]::UtcNow.ToString('o');SensorName='Fixture';SensorRole=$Cfg.SENSOR_ROLE;RunId=$RunId;EvidenceId='old';EndMonoMs=0L;Protocol='TCP_STATS';Status='OK';DataJSON='{}'}
        Add-RingTelemetry $record $record 'TCP_Stats.csv'
        $Clock.ElapsedMilliseconds=301000;$record=$record.PSObject.Copy();$record.EvidenceId='pre';$record.EndMonoMs=301000;Add-RingTelemetry $record $record 'TCP_Stats.csv'
        Assert-MonitorTest ($Ring.Count -eq 1 -and $Ring.Peek().Record.EvidenceId -eq 'pre') 'RAM ring evicts expired samples without any probe CSV on disk'
        Assert-MonitorTest (@(Get-ChildItem -LiteralPath $RunDir -Recurse -File -Filter '*.csv').Count -eq 0) 'Healthy full-rate telemetry is RAM only'
        $Cfg.RingBufferMaxRecords=2
        foreach($id in @('pre2','pre3')){$record=$record.PSObject.Copy();$record.EvidenceId=$id;Add-RingTelemetry $record $record 'TCP_Stats.csv'}
        Assert-MonitorTest ($Ring.Count -eq 2) 'Independent ring record cap bounds burst traffic'
        $path=Start-IncidentRecorder $Assessment
        Assert-MonitorTest (@(Import-Csv -LiteralPath (Join-Path $path 'PreEvent.csv')).Count -eq 2) 'Confirmed incident persists the retained pre-event window'
        $Clock.ElapsedMilliseconds=302000;$record=$record.PSObject.Copy();$record.EvidenceId='during';$record.EndMonoMs=302000;Add-RingTelemetry $record $record 'TCP_Stats.csv'
        Assert-MonitorTest ((Import-Csv -LiteralPath (Join-Path $path 'Event.csv')).EvidenceId -eq 'during') 'Active incident telemetry persists immediately with identity'
        Set-IncidentRecovery
        $Clock.ElapsedMilliseconds=303000;$record=$record.PSObject.Copy();$record.EvidenceId='after';$record.EndMonoMs=303000;Add-RingTelemetry $record $record 'TCP_Stats.csv'
        Assert-MonitorTest ((Import-Csv -LiteralPath (Join-Path $path 'PostEvent.csv')).EvidenceId -eq 'after') 'Recovery starts a separate post-event recording phase'
        $Clock.ElapsedMilliseconds=$script:Recorder.CloseMs
        $record=$record.PSObject.Copy();$record.EvidenceId='too-late';$record.EndMonoMs=$Clock.ElapsedMilliseconds+1;Add-RingTelemetry $record $record 'TCP_Stats.csv'
        Step-Storage
        Assert-MonitorTest (-not $Recorder -and [IO.File]::Exists((Join-Path $path 'Closed.json')) -and @(Import-Csv -LiteralPath (Join-Path $path 'PostEvent.csv')).Count -eq 1) 'Post window closes exactly; later healthy samples are not persisted'
        $Clock.ElapsedMilliseconds+=1;$State.EpisodeId='episode-2';$active=Start-IncidentRecorder $Assessment
        $Storage.Quota=$Storage.Used+$Storage.Reserve+128;$before=$Storage.Used
        $record=$record.PSObject.Copy();$record.DataJSON=('x'*2048);Add-RingTelemetry $record $record 'TCP_Stats.csv'
        Assert-MonitorTest ($Recorder.Dropped -gt 0 -and $Storage.Used -le $Storage.Quota) 'Quota exhaustion suppresses detail before exceeding the quota'
        $Storage.Quota=5GB;Close-IncidentRecorder 'TEST'
        # Force old closed incident pruning while preserving an active recording.
        $Clock.ElapsedMilliseconds+=1;$State.EpisodeId='episode-3';$active=Start-IncidentRecorder $Assessment
        $Storage.Quota=$Storage.Used+1
        Invoke-StorageMaintenance -NeedBytes 512
        Assert-MonitorTest (-not [IO.Directory]::Exists($path) -and [IO.File]::Exists((Join-Path $active 'Active.json'))) 'Quota pruning removes oldest closed incident and preserves active evidence'
        $Storage.Quota=5GB;Close-IncidentRecorder 'COMPRESSION_TEST';Invoke-StorageMaintenance
        $Cfg.CompressClosedIncidents=$true;Invoke-StorageMaintenance;Start-IncidentCompression
        $limit=[Diagnostics.Stopwatch]::StartNew()
        while($Storage.Compression -and $limit.Elapsed.TotalSeconds -lt 15){Step-Storage;Start-Sleep -Milliseconds 20}
        Assert-MonitorTest (-not $Storage.Compression -and @(Get-ChildItem -LiteralPath $IncidentRoot -File -Filter '*.zip').Count -gt 0) ('Closed incidents compress in the background within reserved quota; error='+$script:LastCompressionError)
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $compressed=Get-ChildItem -LiteralPath $IncidentRoot -File -Filter '*.zip' | Select-Object -First 1
        $archive=[IO.Compression.ZipFile]::OpenRead($compressed.FullName)
        try{$entry=$archive.GetEntry('Closed.json');$reader=[IO.StreamReader]::new($entry.Open());try{$metadata=$reader.ReadToEnd() | ConvertFrom-Json}finally{$reader.Dispose()};Assert-MonitorTest ($metadata.SensorName -eq 'Fixture') 'Compressed incident metadata can be decompressed with its sensor identity'}finally{$archive.Dispose()}
        $expired=Join-Path $IncidentRoot 'expired';[void][IO.Directory]::CreateDirectory($expired)
        [IO.File]::WriteAllText((Join-Path $expired 'Closed.json'),(@{SensorName='Fixture';ClosedUTC=[datetime]::UtcNow.AddDays(-31).ToString('o')} | ConvertTo-Json))
        $oldCapture=Join-Path $PacketDir 'old.etl';[IO.File]::WriteAllText($oldCapture,'fixture');[IO.File]::WriteAllText(($oldCapture+'.status.txt'),'StopExit=0');[IO.File]::SetLastWriteTimeUtc($oldCapture,[datetime]::UtcNow.AddDays(-15))
        $oldLog=Join-Path $RunDir 'Logs\19990101\Health.csv';[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($oldLog));[IO.File]::WriteAllText($oldLog,'fixture');[IO.File]::SetLastWriteTimeUtc($oldLog,[datetime]::UtcNow.AddDays(-31))
        Invoke-StorageMaintenance
        Assert-MonitorTest (-not [IO.Directory]::Exists($expired) -and -not [IO.File]::Exists($oldCapture) -and -not [IO.File]::Exists($oldLog) -and [IO.File]::Exists($compressed.FullName)) 'Incident, capture and healthy-log retention expires only aged closed artifacts'
        $Cfg.RingBufferMaxMB=0.001;$record.DataJSON=('x'*4096);Add-RingTelemetry $record $record 'TCP_Stats.csv'
        Assert-MonitorTest ($Ring.Count -eq 0 -and $RingBytes -eq 0) 'Independent RAM payload cap rejects an oversized ring sample'
        $Cfg.RingBufferMaxMB=32;$record.DataJSON='{}';$record.EndMonoMs=$Clock.ElapsedMilliseconds;Add-RingTelemetry $record $record 'TCP_Stats.csv'
        $Cfg.IncidentTelemetryMaxMB=0.0001;$State.EpisodeId='cap-test';[void](Start-IncidentRecorder $Assessment)
        Assert-MonitorTest ($Recorder.Bytes -eq 0 -and $Recorder.Dropped -gt 0) 'Per-incident telemetry cap suppresses detail independently of sensor quota'
        $Cfg.IncidentTelemetryMaxMB=256;Set-IncidentRecovery;$firstDeadline=$Recorder.CloseMs;$Clock.ElapsedMilliseconds+=1000;$State.EpisodeId='relapse';[void](Start-IncidentRecorder $Assessment)
        Assert-MonitorTest ($null -eq $Recorder.CloseMs -and $Recorder.Episodes.Count -eq 2) 'Relapse resumes the existing recording without duplicating its pre-event flush'
        Set-IncidentRecovery;Assert-MonitorTest ($Recorder.CloseMs -gt $firstDeadline) 'Recovery after relapse starts a new full post-event window'
        Close-IncidentRecorder 'TEST'
        $Cfg.NormalLogMaxMB=0.001
        Write-RunLogLine 'Events.log' ('x'*1100);$first=$LogPaths['Events.log'];Write-RunLogLine 'Events.log' 'rotation-check'
        Assert-MonitorTest ($first -ne $LogPaths['Events.log']) 'Normal event logs rotate at the configured size'
        $outside=Join-Path $temp 'outside.txt';$blocked=$false;try{[void](Assert-StoragePath $outside)}catch{$blocked=$true}
        Assert-MonitorTest $blocked 'Storage deletion/write guard rejects paths outside the sensor namespace'
        $locked=$false;$probeLock=$null
        try{$probeLock=[IO.File]::Open((Join-Path $SensorRoot '.sensor.lock'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}catch{$locked=$true}finally{if($probeLock){$probeLock.Dispose()}}
        Assert-MonitorTest $locked 'A second coordinator cannot own the same sensor storage root'
        $Storage.Quota=$Storage.Used+1MB;$Storage.LastPruneMs=$Clock.ElapsedMilliseconds;$priorDropped=$Storage.Dropped;Write-RunLogLine 'Events.log' 'quota-exhausted';$status=Write-ManagedText (Join-Path $RunDir 'Summary_Live.txt') 'priority status' -Critical -Final
        Assert-MonitorTest ($Storage.Dropped -gt $priorDropped -and $status -and $Storage.Used -le $Storage.Quota) 'Final/status headroom survives exhaustion of the normal event allowance'
        $Storage.Quota=5GB;Update-StorageUsage;$actual=[long](Get-ChildItem -LiteralPath $SensorRoot -Recurse -File -Force | Where-Object{$_.Name -ne '.sensor.lock'} | Measure-Object Length -Sum).Sum
        Assert-MonitorTest ($Storage.Used -eq $actual -and -not $Storage.Reservations.Count) ('Storage accounting reconciles actual bytes after worker completion (accounted='+$Storage.Used+' actual='+$actual+' reservations='+$Storage.Reservations.Count+')')
        $script:FatalErrorMessage=$null;Stop-Storage
        Assert-MonitorTest ([IO.File]::Exists((Join-Path $RunDir 'Run_Closed.json'))) 'Graceful storage shutdown marks the run closed'
        $StorageLock.Dispose();$script:StorageLock=$null
        $interrupted=Join-Path $SensorRoot 'Run_interrupted';$unfinished=Join-Path $interrupted 'Incidents\unfinished'
        [void][IO.Directory]::CreateDirectory($unfinished);[IO.File]::WriteAllText((Join-Path $unfinished 'Active.json'),'{}')
        $oldClosed=Join-Path $interrupted 'Incidents\closed';[void][IO.Directory]::CreateDirectory($oldClosed);[IO.File]::WriteAllText((Join-Path $oldClosed 'Closed.json'),(@{SensorName='Fixture';ClosedUTC=[datetime]::UtcNow.ToString('o')} | ConvertTo-Json));[IO.File]::WriteAllText(($oldClosed+'.zip.partial'),'interrupted archive')
        $orphan=Join-Path $interrupted 'PacketCaptures\orphan.etl';[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($orphan));[IO.File]::WriteAllText($orphan,'fixture');[IO.File]::WriteAllText(($orphan+'.capture.json'),(@{SensorName='Fixture';MaxMB=1} | ConvertTo-Json));[IO.File]::SetLastWriteTimeUtc($orphan,[datetime]::UtcNow.AddDays(-100))
        Initialize-Storage
        $closed=[IO.File]::ReadAllText((Join-Path $unfinished 'Closed.json')) | ConvertFrom-Json
        Assert-MonitorTest ($closed.Reason -eq 'INTERRUPTED_PREVIOUS_PROCESS' -and -not $closed.Recovered -and -not [IO.File]::Exists((Join-Path $unfinished 'Active.json'))) 'Exclusive restart marks interrupted incidents closed without fabricating recovery'
        Assert-MonitorTest (-not [IO.File]::Exists($oldClosed+'.zip.partial')) 'Restart removes a recognized abandoned compression partial'
        Assert-MonitorTest ($Storage.Reservations.ContainsKey($orphan) -and $Storage.Reservations[$orphan].Bytes -eq 2MB -and [IO.File]::Exists($orphan)) 'Restart reserves the full native cap and protects an unconfirmed orphan capture'
    }finally{
        if($Recorder){foreach($writer in $Recorder.Writers.Values){$writer.Dispose()};$script:Recorder=$null}
        if($Storage -and $Storage.Compression){$Storage.Compression.PowerShell.Stop();$Storage.Compression.PowerShell.Dispose()}
        foreach($writer in $Writers.Values){$writer.Dispose()}
        if($StorageLock){$StorageLock.Dispose();$script:StorageLock=$null}
        $full=[IO.Path]::GetFullPath($temp);$allowed=(Join-Path ([IO.Path]::GetFullPath([IO.Path]::GetTempPath())) 'NetDiagStorageSelfTest_')
        if($full.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase) -and [IO.Directory]::Exists($full)){Remove-Item -LiteralPath $full -Recurse -Force}
        $script:RunDir=$null;$script:Storage=$null;$script:LogPaths=@{};$script:Writers=@{}
    }
}


function Invoke-HardeningSelfTest {
    $cfg=Read-MonitorConfig (Join-Path (Split-Path $PSScriptRoot -Parent) 'Monitor_Config.psd1')
    $utc=[datetime]::SpecifyKind([datetime]'2026-10-04T11:00:00',[DateTimeKind]::Utc)
    Assert-MonitorTest ((Convert-MonitorUtc $utc) -eq $utc -and (Convert-MonitorUtc '2026-10-04T07:00:00-04:00') -eq $utc) 'UTC DateTime objects and offset strings retain the same instant'
    $cfg.EvidenceEpochMs=20000L
    $rows=@((New-TestObservation ICMP Gateway Local Gateway OK OK 22000),(New-TestObservation ICMP P1 Cloudflare Public FAIL TimedOut 21000),(New-TestObservation ICMP P2 Google Public FAIL TimedOut 21000),(New-TestObservation TCP443 T1 Cloudflare Public FAIL TCP_TIMEOUT 21000),(New-TestObservation TCP443 T2 Google Public FAIL TCP_TIMEOUT 21000))
    foreach($row in $rows){$row.StartMonoMs=19000L}
    $a=Get-CoreAssessment $rows 22000 $cfg
    Assert-MonitorTest ($a.Code -eq 'WAITING_FOR_EVIDENCE' -and -not $a.IncidentEligible) 'Probes spanning a coordinator gap cannot corroborate a new outage'
    $state=New-IncidentState;$state.Active='UPSTREAM_WAN_CONFIRMED';$state.RecoveryFirstMs=10000;$state.RecoveryStreams=@{ICMP=10000};$state.Candidate='UPSTREAM_WAN_CONFIRMED'
    Reset-IncidentAfterGap $state
    Assert-MonitorTest ($state.Active -eq 'UPSTREAM_WAN_CONFIRMED' -and $null -eq $state.RecoveryFirstMs -and $null -eq $state.Candidate) 'Sensor gap resets recovery hold and candidates while retaining confirmed incidents'
    $job=[pscustomobject]@{Handle=[pscustomobject]@{IsCompleted=$false};StartedMs=100L}
    Reset-InFlightBudgetAfterGap ([pscustomobject]@{Jobs=@{DNS=$job}}) 245800000L
    Assert-MonitorTest ($job.StartedMs -eq 245800000L) 'In-flight worker receives a fresh bounded budget after resume'
    $progress=New-SupervisorProgress 0L
    $hb=[pscustomobject]@{Token='owned';ProcessId=123;ProcessStartedUTC='start';MonoMs=1L;Status='RUNNING'}
    $decision=Update-SupervisorProgress $progress $hb 'owned' 123 'start' 1000 120000 90000
    Assert-MonitorTest ($decision.Valid -and $progress.HasHeartbeat -and -not $decision.Restart) 'Supervisor accepts only its owned child heartbeat'
    $hb.Token='wrong';$hb.MonoMs=20000
    $decision=Update-SupervisorProgress $progress $hb 'owned' 123 'start' 2000 120000 90000
    Assert-MonitorTest (-not $decision.Valid -and $progress.ChildMonoMs -eq 1) 'Unrelated heartbeat cannot keep a stalled child alive'
    $hb.Token='owned';$hb.MonoMs=1L
    foreach($tick in 10000L,20000L,30000L,40000L,50000L,60000L,70000L,80000L,90000L,92000L){$decision=Update-SupervisorProgress $progress $hb 'owned' 123 'start' $tick 120000 90000}
    Assert-MonitorTest $decision.Restart 'Frozen owned heartbeat exceeds the independent 90-second stall budget'
    $decision=Update-SupervisorProgress $progress $hb 'owned' 123 'start' 245800000L 120000 90000
    Assert-MonitorTest ($decision.SupervisorGap -and -not $decision.Restart) 'Supervisor suspension grants resume grace rather than fabricating a child stall'
    $progress=New-SupervisorProgress 0L
    foreach($tick in 10000L,20000L,30000L,40000L,50000L,60000L,70000L,80000L,90000L,100000L,110000L,120000L,121000L){$decision=Update-SupervisorProgress $progress $null 'owned' 123 'start' $tick 120000 90000}
    Assert-MonitorTest $decision.Restart 'Child with no first heartbeat exceeds the separate startup deadline'
    # Mock only device discovery. The actual context assembly/classification executes.
    function Get-NetRoute { [pscustomobject]@{NextHop='192.168.50.1';InterfaceIndex=7;RouteMetric=1} }
    function Get-NetIPInterface { [pscustomobject]@{InterfaceMetric=1} }
    function Get-NetAdapter { [pscustomobject]@{Name='Fixture';LinkSpeed='2.5 Gbps'} }
    function Get-DnsClientServerAddress { [pscustomobject]@{ServerAddresses=@('1.1.1.1')} }
    $cfg.SENSOR_ROLE='BEHIND_ASUS';$cfg.EnableRouterDnsProbe=$false;$cfg.EnableBgwDnsProbe=$false
    $ctx=Get-SensorContext $cfg
    Assert-MonitorTest (@($ctx.Targets | Where-Object{$_.Role -eq 'Gateway2'}).Count -eq 1 -and @($ctx.AllDnsResolvers | Where-Object{$_.Scope -in @('RouterDNS','BgwDNS')}).Count -eq 0) 'BGW management probe does not implicitly require DNS proxy service'
    $cfg.EnableRouterDnsProbe=$true;$cfg.EnableBgwDnsProbe=$true
    $ctx=Get-SensorContext $cfg
    Assert-MonitorTest (@($ctx.AllDnsResolvers | Where-Object{$_.Scope -in @('RouterDNS','BgwDNS')}).Count -eq 2) 'Verified DNS proxies can be enabled independently'
    $cfg.SystemDnsIP='192.168.50.1';$cfg.EnableRouterDnsProbe=$false;$cfg.EnableBgwDnsProbe=$false
    $ctx=Get-SensorContext $cfg
    Assert-MonitorTest (@($ctx.AllDnsResolvers | Where-Object{$_.Scope -eq 'RouterDNS'}).Count -eq 1) 'Configured system DNS is always measured even when optional proxies are off'
    $script:WatchActive=@{};$script:WatchLogAt=@{};$script:WatchLoggedActive=@{};$script:Clock=[pscustomobject]@{ElapsedMilliseconds=0L};$script:Cfg=$cfg;$script:HistoryFixture=[Collections.Generic.List[string]]::new()
    $Clock=$script:Clock;$Cfg=$script:Cfg;$HistoryFixture=$script:HistoryFixture
    function Write-HistoryLog {param($Type,$Message);$script:HistoryFixture.Add($Type)}
    $watch=[pscustomobject]@{Key='ICMP:Endpoint';Severity='WATCH';Text='Endpoint-specific failure'}
    Update-WatchHistory @($watch);Update-WatchHistory @();$Clock.ElapsedMilliseconds=1000;Update-WatchHistory @($watch);Update-WatchHistory @()
    Assert-MonitorTest ($HistoryFixture.Count -eq 2 -and $HistoryFixture[0] -eq 'WATCH_START' -and $HistoryFixture[1] -eq 'WATCH_CLEAR') 'Repeated endpoint chatter is throttled while preserving the first start/clear pair'
    $Clock.ElapsedMilliseconds=300000;Update-WatchHistory @($watch)
    Assert-MonitorTest ($HistoryFixture.Count -eq 3 -and $WatchActive.ContainsKey($watch.Key)) 'Endpoint remains visible live and persists again after cooldown'
}
