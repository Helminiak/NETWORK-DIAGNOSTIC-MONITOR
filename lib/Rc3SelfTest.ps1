function Invoke-Rc3SelfTest {
    $cfg=Read-MonitorConfig (Join-Path (Split-Path $PSScriptRoot -Parent) 'Monitor_Config.psd1')
    foreach($ip in @('10.0.0.1','172.16.0.1','172.31.255.255','192.168.50.1','127.0.0.1','169.254.1.2','100.64.0.1','100.127.255.254','192.0.2.1','198.51.100.1','203.0.113.1','198.18.0.1','224.0.0.1','0.0.0.0','255.255.255.255','::1','garbage')){
        Assert-MonitorTest (-not (Test-PublicProbeAddress $ip)) ('Nonpublic/unsupported address rejected: '+$ip)
    }
    foreach($ip in @('1.1.1.1','8.8.8.8','172.32.0.1','100.128.0.1')){Assert-MonitorTest (Test-PublicProbeAddress $ip) ('Public boundary accepted: '+$ip)}
    Assert-MonitorTest ((Get-DnsAnswerPolicy 'www.google.com' @('8.8.8.8','10.0.0.1') $cfg) -eq 'PUBLIC_NAME_NONPUBLIC_ANSWER') 'Mixed public/private answer sets are anomalous'
    $cfg.AllowedPrivateDnsNames=@('internal.example')
    Assert-MonitorTest ((Get-DnsAnswerPolicy 'internal.example' @('10.0.0.1') $cfg) -eq 'EXEMPT' -and (Get-DnsAnswerPolicy 'other.internal.example' @('10.0.0.1') $cfg) -ne 'EXEMPT') 'Private-answer exemption is exact-name and does not wildcard subdomains'
    $rows=@()
    foreach($provider in @('Cloudflare','Google')){foreach($name in @('www.apple.com','www.google.com')){
        $row=New-TestObservation DNS_UDP $provider $provider ExternalDNS OK NOERROR
        $row.Data.QueryName=$name;$row.Data.Addresses=@('10.0.0.1');$rows+=$row
    }}
    $a=Get-CoreAssessment $rows 10000 $cfg
    Assert-MonitorTest ($a.Code -eq 'DNS_ANSWER_REDIRECTION' -and $a.IncidentEligible -and $a.CaptureEligible) 'Wire-success private answers across providers/names form a DNS integrity incident'
    $oneName=@($rows | Where-Object{$_.Data.QueryName -eq 'www.apple.com'})
    $gw=New-TestObservation ICMP Gateway Local Gateway OK OK
    $icmp=@((New-TestObservation ICMP C Cloudflare Public FAIL TimedOut),(New-TestObservation ICMP G Google Public FAIL TimedOut))
    $tcp=@((New-TestObservation TCP443 C Cloudflare Public FAIL TCP_TIMEOUT),(New-TestObservation TCP443 G Google Public FAIL TCP_TIMEOUT))
    foreach($row in $tcp){$row.Data.IP='10.0.0.1';$row.Data.HostName='www.google.com'}
    $a=Get-CoreAssessment ($oneName+@($gw)+$icmp+$tcp) 10000 $cfg
    Assert-MonitorTest ($a.Code -eq 'DNS_INTEGRITY_WATCH' -and -not $a.IncidentEligible) 'Private-IP named TCP failures and ICMP cannot falsely corroborate a WAN incident'
    foreach($row in $tcp){$row.Data.IP='8.8.8.8';$row.Data.HostName='8.8.8.8';$row.Data.ResolutionMode='PINNED_IP'}
    $a=Get-CoreAssessment (@($gw)+$icmp+$tcp) 10000 $cfg
    Assert-MonitorTest ($a.Code -eq 'UPSTREAM_WAN_CONFIRMED') 'Pinned public TCP and independent ICMP retain correlated path classification'
    $state=New-IncidentState;$a=Get-CoreAssessment $rows 10000 $cfg
    [void](Update-IncidentState $state $a $rows 10000 $cfg)
    foreach($row in $rows){$row.StartMonoMs=14900;$row.EndMonoMs=15000}
    $a=Get-CoreAssessment $rows 15000 $cfg;$actions=@(Update-IncidentState $state $a $rows 15000 $cfg)
    Assert-MonitorTest ($actions -contains 'INCIDENT') 'Advancing DNS integrity evidence confirms after debounce'
    foreach($row in $rows){$row.StartMonoMs=19900;$row.EndMonoMs=20000}
    $neutral=New-Assessment HEALTHY OK 'Fixture neutral assessment'
    $actions=@(Update-IncidentState $state $neutral $rows 20000 $cfg)
    Assert-MonitorTest ($null -eq $state.RecoveryFirstMs -and $state.Active) 'Wire-success redirected DNS cannot start recovery even under a neutral assessment'
    foreach($row in $rows){$row.Data.Addresses=@('1.1.1.1');$row.StartMonoMs=24900;$row.EndMonoMs=25000}
    $actions=@(Update-IncidentState $state $neutral $rows 25000 $cfg)
    foreach($row in $rows){$row.StartMonoMs=30900;$row.EndMonoMs=31000}
    $actions=@(Update-IncidentState $state $neutral $rows 31000 $cfg)
    Assert-MonitorTest ($actions -contains 'RECOVERY') 'Public answers advancing through a full hold recover DNS integrity incident'
    $udp=@();$tcp53=@()
    foreach($provider in @('Cloudflare','Google')){$udp+=New-TestObservation DNS_UDP $provider $provider ExternalDNS OK NOERROR 12000;$tcp53+=New-TestObservation DNS_TCP $provider $provider ExternalDNS FAIL DNS_TCP_CONNECT_TIMEOUT 11900}
    $a=Get-CoreAssessment ($udp+$tcp53) 12000 $cfg
    Assert-MonitorTest ($a.Code -eq 'DNS_TCP_PATH_WATCH' -and -not $a.IncidentEligible) 'Healthy UDP does not hide selective multi-provider TCP53 failure'
    Assert-MonitorTest ((Get-EvidenceStreamKey $udp[0]) -ne (Get-EvidenceStreamKey $tcp53[0])) 'Recovery stream identity preserves DNS transport'
    # Replace only DNS in this scope; no private network connection can be attempted.
    function Invoke-DnsQuery {param($Server,$Name,$TimeoutMs);[pscustomobject]@{Status='OK';Stage='NOERROR';Ms=1;Addresses=@('10.0.0.1')}}
    $Cfg=$cfg
    $blocked=Invoke-TcpProbe 'www.google.com' 443 '127.0.0.1' 100 100
    Assert-MonitorTest (-not $blocked.TcpAttempted -and $blocked.Stage -eq 'DNS_ANSWER_NONPUBLIC' -and $null -eq $blocked.Ms) 'Public hostname redirected to private IP is blocked before socket creation'
    $q=New-DnsQueryPacket 'example.com' 123
    [byte[]]$unrelated=@($q);$unrelated[2]=129;$unrelated[3]=128;$unrelated[7]=1
    [byte[]]$owner=@(5,111,116,104,101,114,3,99,111,109,0)
    $unrelated+= $owner+[byte[]]@(0,1,0,1,0,0,0,60,0,4,1,1,1,1)
    $parsed=Get-DnsPacketResult $unrelated 123 'example.com'
    Assert-MonitorTest (-not $parsed.Success -and $parsed.RCode -eq 'NO_A_ANSWER') 'Unrelated A record cannot satisfy the requested DNS name'
    [byte[]]$valid=@($q);$valid[2]=129;$valid[3]=128;$valid[7]=2
    $valid+=[byte[]]@(192,12,0,5,0,1,0,0,0,60,0,11)+$owner
    $valid+=$owner+[byte[]]@(0,1,0,1,0,0,0,60,0,4,1,1,1,1)
    $parsed=Get-DnsPacketResult $valid 123 'example.com'
    Assert-MonitorTest ($parsed.Success -and $parsed.Addresses[0] -eq '1.1.1.1') 'Question-linked CNAME chain can satisfy the requested DNS name'
    $history=New-Object Collections.ArrayList
    Add-HistorySample $history $true 2 'OK' ([datetime]'2000-01-01')
    Add-HistorySample $history $true 4 'OK' ([datetime]'2100-01-01')
    $rolling=Get-RollingStats $history
    Assert-MonitorTest ($rolling.Count -eq 2 -and $rolling.Avg -eq 3) 'Civil-clock jumps do not evict current rolling observations'
    $pinned=@($cfg.TcpConnectTargets | Where-Object{$_.Name -like '*-Pinned'})
    Assert-MonitorTest ($pinned.Count -eq 2 -and @($pinned.Provider | Sort-Object -Unique).Count -eq 2) 'Default configuration has two providers of DNS-independent TCP controls'
    $before=@{Name='Wi-Fi';RxBytes=1000L;TxBytes=1000L};$after=@{Name='Wi-Fi';RxBytes=1251000L;TxBytes=251000L}
    $rate=Get-InterfaceTrafficDelta $after $before 10000 0 30
    Assert-MonitorTest ($rate.RxMbps -eq 1 -and $rate.TxMbps -eq 0.2 -and $rate.CounterState -eq 'DELTA') 'Byte counters become Mbps through elapsed monotonic time'
    $rate=Get-InterfaceTrafficDelta $after $before 100000 0 30
    Assert-MonitorTest ($null -eq $rate.RxMbps -and $rate.CounterState -eq 'SAMPLING_GAP') 'Long sampling gap does not fabricate current throughput'
    $rate=Get-InterfaceTrafficDelta $before $after 10000 0 30
    Assert-MonitorTest ($null -eq $rate.RxMbps -and $rate.CounterState -eq 'RESET_OR_INTERFACE_CHANGE') 'Counter reset is unknown throughput rather than zero'
    $after.Name='Ethernet';$rate=Get-InterfaceTrafficDelta $after $before 10000 0 30
    Assert-MonitorTest ($null -eq $rate.RxMbps) 'Changing adapters cannot mix traffic counters'
    $rate=Get-InterfaceTrafficDelta $after $null 10000 $null 30
    Assert-MonitorTest ($rate.CounterState -eq 'BASELINE' -and $null -eq $rate.TxMbps) 'First counter sample is baseline rather than invented traffic'

    $curl=(Get-Command curl.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if(-not $curl){$curl=(Get-Command curl -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source}
    if($curl){
        if(-not ('NetDiagHttpMethodFixture' -as [type])){
            Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
public sealed class NetDiagHttpMethodFixture : IDisposable {
    TcpListener listener; Thread worker; volatile bool stop;
    public int Port; public volatile string LastMethod;
    public NetDiagHttpMethodFixture() {
        listener=new TcpListener(IPAddress.Loopback,0);listener.Start();Port=((IPEndPoint)listener.LocalEndpoint).Port;
        worker=new Thread(Serve);worker.IsBackground=true;worker.Start();
    }
    void Serve() { try { while(!stop) { using(TcpClient client=listener.AcceptTcpClient()) {
        client.ReceiveTimeout=1000;client.SendTimeout=1000;NetworkStream stream=client.GetStream();
        StreamReader reader=new StreamReader(stream,Encoding.ASCII,false,1024,true);
        string first=reader.ReadLine();LastMethod=first.Split(' ')[0];
        string line;while((line=reader.ReadLine())!=null && line.Length>0){}
        byte[] body=Encoding.ASCII.GetBytes("{\"Status\":0}");
        int length=LastMethod=="HEAD"?1048576:body.Length;
        byte[] headers=Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: "+length+"\r\nConnection: close\r\n\r\n");
        stream.Write(headers,0,headers.Length);if(LastMethod!="HEAD")stream.Write(body,0,body.Length);
    }}}catch{if(!stop)throw;} }
    public void Dispose(){stop=true;listener.Stop();worker.Join(1500);}
}
'@
        }
        $fixture=New-Object NetDiagHttpMethodFixture
        $oldLocation=Get-Location;$temp=Join-Path ([IO.Path]::GetTempPath()) ('NetDiagHttp_'+[guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($temp)
        try{
            Set-Location -LiteralPath $temp
            $Ctx=@{CurlExe=$curl}
            $headers=Invoke-CurlTiming ('http://127.0.0.1:'+$fixture.Port+'/') 2
            Assert-MonitorTest ($headers.Status -eq 'OK' -and $fixture.LastMethod -eq 'HEAD' -and $headers.Measurement -eq 'HEAD_HEADERS_ONLY') 'Actual curl uses HEAD and completes a large advertised response without body download'
            $endpoint=Invoke-CurlTiming ('http://127.0.0.1:'+$fixture.Port+'/') 2 -Doh
            Assert-MonitorTest ($endpoint.Status -eq 'OK' -and $fixture.LastMethod -eq 'GET' -and $endpoint.Measurement -eq 'DOH_ENDPOINT_ONLY') 'DoH endpoint sampler retains GET and explicit endpoint-only scope'
            $Ctx.CurlExe=Join-Path $temp 'missing-curl-executable'
            $missing=Invoke-CurlTiming ('http://127.0.0.1:'+$fixture.Port+'/') 2
            Assert-MonitorTest ($missing.Status -eq 'UNAVAILABLE' -and $missing.Stage -eq 'CURL_RUNTIME_ERROR') 'External tool startup failure remains unavailable evidence rather than crashing the coordinator'
        }finally{Set-Location -LiteralPath $oldLocation.Path;$fixture.Dispose();Remove-Item -LiteralPath $temp -Recurse -Force}
    }else{Write-Host 'SKIP Loopback curl method fixture: curl executable unavailable.'}

}
