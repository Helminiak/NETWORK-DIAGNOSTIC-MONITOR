# Worker adapters. They publish immutable, platform-neutral observations to a queue.
# No console rendering, classification, or CSV writes occur in a probe worker.
. (Join-Path $PSScriptRoot 'AddressPolicy.ps1')
function Publish-Probe {
    param($Target,[string]$Protocol,[string]$Scope,[long]$StartMs,[datetime]$StartedUTC,$Result)
    $provider = if($Target.Provider){$Target.Provider}elseif($Target.Class -eq 'ATT'){'ATT'}else{$Target.Name}
    $record = [pscustomobject][ordered]@{
        SchemaVersion=1; EvidenceId=[guid]::NewGuid().ToString('N'); SweepId=$SweepId
        Family=$Family; Protocol=$Protocol; Name=$Target.Name; Provider=$provider; Scope=$Scope
        StartedUTC=$StartedUTC.ToString('o'); CompletedUTC=[datetime]::UtcNow.ToString('o')
        StartMonoMs=$StartMs; EndMonoMs=[long]$Clock.ElapsedMilliseconds
        Status=$Result.Status; Stage=$Result.Stage; LatencyMs=$Result.Ms; Data=$Result
    }
    $Queue.Enqueue($record)
}

function Get-ProbeExceptionDetails {
    param([Exception]$Exception)
    $cause=$Exception.GetBaseException()
    $message=($cause.Message -replace '[\r\n\t]',' ')
    if($message.Length -gt 256){$message=$message.Substring(0,256)}
    [pscustomobject]@{type=$cause.GetType().FullName;message=$message;socketError=if($cause -is [Net.Sockets.SocketException]){[string]$cause.SocketErrorCode}else{$null};nativeErrorCode=if($cause -is [Net.Sockets.SocketException]){$cause.NativeErrorCode}else{$null}}
}

function Read-DnsName {
    param([byte[]]$Bytes,[ref]$Offset)
    $labels=New-Object 'System.Collections.Generic.List[string]'
    $cursor=[int]$Offset.Value; $resume=-1; $steps=0
    while($true){
        if($cursor -ge $Bytes.Length -or ++$steps -gt 128){throw 'Invalid DNS name.'}
        $n=[int]$Bytes[$cursor]; $cursor++
        if($n -eq 0){break}
        if(($n -band 192) -eq 192){
            if($cursor -ge $Bytes.Length){throw 'Short DNS pointer.'}
            if($resume -lt 0){$resume=$cursor+1}
            $cursor=(($n -band 63) -shl 8) -bor [int]$Bytes[$cursor]; continue
        }
        if($n -gt 63 -or $cursor+$n -gt $Bytes.Length){throw 'Invalid DNS label.'}
        $labels.Add([Text.Encoding]::ASCII.GetString($Bytes,$cursor,$n)); $cursor+=$n
    }
    $Offset.Value=if($resume -ge 0){$resume}else{$cursor}
    return ($labels -join '.')
}

function New-DnsQueryPacket {
    param([string]$Name,[uint16]$Id)
    $asciiName=([Globalization.IdnMapping]::new()).GetAscii($Name.Trim('.'))
    if($asciiName.Length -lt 1 -or $asciiName.Length -gt 253){throw 'Invalid DNS query name.'}
    $bytes=New-Object 'System.Collections.Generic.List[byte]'
    $bytes.AddRange([byte[]]@([byte]($Id -shr 8),[byte]($Id -band 255),1,0,0,1,0,0,0,0,0,0))
    foreach($label in $asciiName.Split('.')){
        $b=[Text.Encoding]::ASCII.GetBytes($label)
        if($b.Length -lt 1 -or $b.Length -gt 63){throw 'Invalid DNS label.'}
        $bytes.Add([byte]$b.Length); $bytes.AddRange($b)
    }
    $bytes.AddRange([byte[]]@(0,0,1,0,1))
    return ,$bytes.ToArray()
}

function Get-DnsPacketResult {
    param([byte[]]$Bytes,[uint16]$ExpectedId,[string]$ExpectedName)
    $result=[pscustomobject]@{Success=$false; RCode='MALFORMED_RESPONSE'; Answers=0; Truncated=$false; Addresses=@()}
    try{
        if($Bytes.Length -lt 12){$result.RCode='SHORT_RESPONSE';return $result}
        if((([int]$Bytes[0] -shl 8) -bor [int]$Bytes[1]) -ne $ExpectedId){$result.RCode='ID_MISMATCH';return $result}
        if(($Bytes[2] -band 128) -eq 0 -or ($Bytes[2] -band 120) -ne 0){return $result}
        $result.Truncated=($Bytes[2] -band 2) -ne 0
        if($result.Truncated){$result.RCode='TRUNCATED';return $result}
        $rcode=$Bytes[3] -band 15
        $result.RCode=switch($rcode){0{'NOERROR'}1{'FORMERR'}2{'SERVFAIL'}3{'NXDOMAIN'}4{'NOTIMP'}5{'REFUSED'}default{"RCODE_$rcode"}}
        $questions=([int]$Bytes[4] -shl 8) -bor [int]$Bytes[5]
        $answers=([int]$Bytes[6] -shl 8) -bor [int]$Bytes[7]
        if($questions -ne 1){$result.RCode='QUESTION_MISMATCH';return $result}
        $offset=12; $name=Read-DnsName $Bytes ([ref]$offset)
        if($ExpectedName -and $name -ne $ExpectedName.Trim('.')){$result.RCode='QUESTION_MISMATCH';return $result}
        if($offset+4 -gt $Bytes.Length -or $Bytes[$offset] -ne 0 -or $Bytes[$offset+1] -ne 1 -or $Bytes[$offset+2] -ne 0 -or $Bytes[$offset+3] -ne 1){throw 'Invalid DNS question.'}
        $offset+=4; $addresses=New-Object 'System.Collections.Generic.List[string]';$records=New-Object Collections.ArrayList
        for($i=0;$i -lt $answers;$i++){
            $owner=Read-DnsName $Bytes ([ref]$offset)
            if($offset+10 -gt $Bytes.Length){throw 'Short DNS answer.'}
            $type=([int]$Bytes[$offset] -shl 8) -bor [int]$Bytes[$offset+1]
            $class=([int]$Bytes[$offset+2] -shl 8) -bor [int]$Bytes[$offset+3]
            $length=([int]$Bytes[$offset+8] -shl 8) -bor [int]$Bytes[$offset+9]; $offset+=10
            if($offset+$length -gt $Bytes.Length){throw 'Short DNS RDATA.'}
            if($type -eq 1 -and $class -eq 1 -and $length -eq 4){[void]$records.Add(@{Owner=$owner;Type=1;Address=($Bytes[$offset..($offset+3)] -join '.')})}
            if($type -eq 5 -and $class -eq 1){$cnameOffset=$offset;$canonical=Read-DnsName $Bytes ([ref]$cnameOffset);if($cnameOffset -ne $offset+$length){throw 'Invalid CNAME length.'};[void]$records.Add(@{Owner=$owner;Type=5;Canonical=$canonical})}
            $offset+=$length
        }
        $accepted=@{};$accepted[$name.ToLowerInvariant()]=$true
        for($chain=0;$chain -lt 16;$chain++){
            $added=$false
            foreach($rr in $records){if($rr.Type -eq 5 -and $accepted.ContainsKey($rr.Owner.ToLowerInvariant()) -and -not $accepted.ContainsKey($rr.Canonical.ToLowerInvariant())){$accepted[$rr.Canonical.ToLowerInvariant()]=$true;$added=$true}}
            if(-not $added){break}
        }
        foreach($rr in $records){if($rr.Type -eq 1 -and $accepted.ContainsKey($rr.Owner.ToLowerInvariant())){$addresses.Add($rr.Address)}}
        $result.Answers=$answers; $result.Addresses=@($addresses)
        $result.Success=($rcode -eq 0 -and $addresses.Count -gt 0)
        if($rcode -eq 0 -and -not $result.Success){$result.RCode='NO_A_ANSWER'}
    }catch{$result.RCode='MALFORMED_RESPONSE';$result.Success=$false}
    return $result
}

function Get-RemainingMs {
    param($Watch,[int]$TimeoutMs)
    $remaining=$TimeoutMs-[int]$Watch.ElapsedMilliseconds
    if($remaining -le 0){throw [TimeoutException]::new('Transaction deadline expired.')}
    return $remaining
}

function Read-ExactNetworkBytes {
    param($Stream,[int]$Count,$Watch,[int]$TimeoutMs)
    $buf=New-Object byte[] $Count; $offset=0
    while($offset -lt $Count){
        $Stream.ReadTimeout=Get-RemainingMs $Watch $TimeoutMs
        $n=$Stream.Read($buf,$offset,$Count-$offset)
        if($n -le 0){throw [IO.EndOfStreamException]::new('DNS TCP peer closed the stream.')}
        $offset+=$n
    }
    return ,$buf
}

function Invoke-DnsQuery {
    param([string]$Server,[string]$Name,[int]$TimeoutMs,[switch]$Tcp,[int]$Port=53)
    $id=[uint16](Get-Random -Minimum 1 -Maximum 65535)
    $query=New-DnsQueryPacket $Name $id
    $watch=[Diagnostics.Stopwatch]::StartNew(); $client=$null; $handle=$null; $phase='CONNECT'
    $result=[pscustomobject]@{Status='FAIL';Stage='DNS_ERROR';Ms=$null;RCode='';Addresses=@();QueryName=$Name;IP=$Server;AnswerPolicy='NO_ADDRESS';Error=$null}
    try{
        if($Tcp){
            $client=[Net.Sockets.TcpClient]::new()
            $async=$client.BeginConnect($Server,$Port,$null,$null);$handle=$async.AsyncWaitHandle
            if(-not $handle.WaitOne((Get-RemainingMs $watch $TimeoutMs))){throw [TimeoutException]::new('DNS TCP connect timeout.')}
            $client.EndConnect($async);$stream=$client.GetStream();$phase='RESPONSE'
            $stream.WriteTimeout=Get-RemainingMs $watch $TimeoutMs
            [byte[]]$framed=@([byte]($query.Length -shr 8),[byte]($query.Length -band 255))+$query
            $stream.Write($framed,0,$framed.Length)
            $len=Read-ExactNetworkBytes $stream 2 $watch $TimeoutMs
            $n=([int]$len[0] -shl 8) -bor [int]$len[1]
            if($n -lt 12){throw [IO.InvalidDataException]::new('Short DNS TCP response length.')}
            $response=Read-ExactNetworkBytes $stream $n $watch $TimeoutMs
        }else{
            $client=[Net.Sockets.UdpClient]::new();$client.Connect($Server,$Port)
            $client.Client.SendTimeout=Get-RemainingMs $watch $TimeoutMs
            [void]$client.Send($query,$query.Length);$phase='RESPONSE'
            $client.Client.ReceiveTimeout=Get-RemainingMs $watch $TimeoutMs
            $peer=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
            $response=$client.Receive([ref]$peer)
        }
        $parsed=Get-DnsPacketResult $response $id $Name
        $result.RCode=$parsed.RCode;$result.Addresses=$parsed.Addresses
        $result.AnswerPolicy=Get-DnsAnswerPolicy $Name $parsed.Addresses $Cfg
        $result.Status=if($parsed.Success){'OK'}else{'FAIL'};$result.Stage=$parsed.RCode
    }catch{
        $timed=($_.Exception -is [TimeoutException] -or $watch.ElapsedMilliseconds -ge $TimeoutMs -or $_.Exception.ToString() -match '10060|timed out')
        $result.Stage=if($timed){if($Tcp -and $phase -eq 'CONNECT'){'DNS_TCP_CONNECT_TIMEOUT'}else{'DNS_TIMEOUT'}}else{'DNS_SOCKET_ERROR'}
        $result.RCode=$result.Stage;$result.Error=Get-ProbeExceptionDetails $_.Exception
    }finally{if($client){$client.Close()};if($handle){$handle.Close()}}
    $result.Ms=[math]::Round($watch.Elapsed.TotalMilliseconds,1)
    return $result
}

function Invoke-IcmpFamily {
    $pending=New-Object System.Collections.ArrayList; $index=0; $nextStart=[long]0
    try{
        while($index -lt $Ctx.Targets.Count -or $pending.Count -gt 0){
            $now=$Clock.ElapsedMilliseconds
            if($index -lt $Ctx.Targets.Count -and $pending.Count -lt $Cfg.PingConcurrency -and $now -ge $nextStart){
                $target=$Ctx.Targets[$index++];$ping=[Net.NetworkInformation.Ping]::new()
                $started=[datetime]::UtcNow;$start=$Clock.ElapsedMilliseconds
                try{
                    $task=$ping.SendPingAsync($target.IP,[int]$Cfg.PingTimeoutMs)
                    [void]$pending.Add([pscustomobject]@{Target=$target;Ping=$ping;Task=$task;Started=$started;Start=$start})
                }catch{ $ping.Dispose();Publish-Probe $target 'ICMP' $target.Role $start $started @{Status='FAIL';Stage='PING_ERROR';Ms=$null;IP=$target.IP} }
                $nextStart=$start+$Cfg.PingStaggerMs
            }
            foreach($item in @($pending)){
                if(-not $item.Task.IsCompleted -and $Clock.ElapsedMilliseconds-$item.Start -lt $Cfg.PingTimeoutMs+500){continue}
                $status='FAIL';$stage='TimedOut';$ms=$null
                if($item.Task.IsCompleted -and -not $item.Task.IsFaulted -and -not $item.Task.IsCanceled){
                    $reply=$item.Task.Result;$stage=[string]$reply.Status
                    if($stage -eq 'Success'){$status='OK';$stage='OK';$ms=[double]$reply.RoundtripTime}
                }elseif($item.Task.IsFaulted){$stage='PING_ERROR'}
                Publish-Probe $item.Target 'ICMP' $item.Target.Role $item.Start $item.Started @{Status=$status;Stage=$stage;Ms=$ms;IP=$item.Target.IP}
                $item.Ping.Dispose();$pending.Remove($item)
            }
            Start-Sleep -Milliseconds 5
        }
    }finally{foreach($item in $pending){$item.Ping.Dispose()}}
}

function Invoke-DnsFamily {
    foreach($target in $Ctx.AllDnsResolvers){
        $start=$Clock.ElapsedMilliseconds;$utc=[datetime]::UtcNow
        $result=Invoke-DnsQuery $target.IP $QueryName $Cfg.DnsTimeoutMs
        Publish-Probe $target 'DNS_UDP' $target.Scope $start $utc $result
        Start-Sleep -Milliseconds 50
    }
}

function Resolve-ProbeName {
    param([string]$Resolver,[string]$Name,[int]$TimeoutMs,[int]$Port=53,[int]$TcpPort=0)
    if($TcpPort -eq 0){$TcpPort=$Port}
    $deadline=[Diagnostics.Stopwatch]::StartNew()
    $result=Invoke-DnsQuery $Resolver $Name $TimeoutMs -Port $Port
    $transport='DNS_UDP';$fallback=$null
    if($result.Stage -eq 'TRUNCATED'){
        $fallback='TRUNCATED';$transport='DNS_TCP_FALLBACK'
        $remaining=$TimeoutMs-[int]$deadline.ElapsedMilliseconds
        if($remaining -gt 0){$result=Invoke-DnsQuery $Resolver $Name $remaining -Tcp -Port $TcpPort}
        else{$result.Status='FAIL';$result.Stage='DNS_TIMEOUT';$result.RCode='DNS_TIMEOUT'}
    }
    $result.Ms=[math]::Round($deadline.Elapsed.TotalMilliseconds,1)
    $result | Add-Member NoteProperty DnsTransport $transport -Force
    $result | Add-Member NoteProperty DnsFallbackReason $fallback -Force
    return $result
}

function Invoke-TcpProbe {
    param([string]$HostName,[int]$Port,[string]$Resolver,[int]$DnsTimeoutMs,[int]$TimeoutMs)
    $ip=$null;$dnsMs=0;$parsedIP=$null
    if([Net.IPAddress]::TryParse($HostName,[ref]$parsedIP)){$ip=$parsedIP.IPAddressToString}else{
        # Bounded direct query to the configured sensor resolver, not an uncancellable OS task.
        $dns=Resolve-ProbeName $Resolver $HostName $DnsTimeoutMs;$dnsMs=$dns.Ms
        if($dns.Status -ne 'OK'){return @{Status='FAIL';Stage=if($dns.Stage -match 'TIMEOUT'){'DNS_TIMEOUT'}else{'DNS_FAIL'};Ms=$null;DNSms=$dnsMs;IP='';Port=$Port;HostName=$HostName;TcpAttempted=$false;DnsDetail=$dns.Stage;Error=$dns.Error;DnsTransport=$dns.DnsTransport;DnsFallbackReason=$dns.DnsFallbackReason}}
        if((Get-DnsAnswerPolicy $HostName $dns.Addresses $Cfg) -eq 'PUBLIC_NAME_NONPUBLIC_ANSWER'){
            return @{Status='FAIL';Stage='DNS_ANSWER_NONPUBLIC';Ms=$null;DNSms=$dnsMs;IP=($dns.Addresses -join ',');Port=$Port;HostName=$HostName;TcpAttempted=$false;AnswerPolicy='PUBLIC_NAME_NONPUBLIC_ANSWER';Addresses=$dns.Addresses;DnsTransport=$dns.DnsTransport;DnsFallbackReason=$dns.DnsFallbackReason}
        }
        $ip=$dns.Addresses[0]
    }
    $client=[Net.Sockets.TcpClient]::new();$watch=[Diagnostics.Stopwatch]::StartNew();$handle=$null
    $status='FAIL';$stage='TCP_ERROR';$errorDetails=$null
    try{
        $async=$client.BeginConnect($ip,$Port,$null,$null);$handle=$async.AsyncWaitHandle
        if($handle.WaitOne($TimeoutMs)){$client.EndConnect($async);$status='OK';$stage='OK'}else{$stage='TCP_TIMEOUT'}
    }catch{$stage='TCP_ERROR';$errorDetails=Get-ProbeExceptionDetails $_.Exception}finally{$client.Close();if($handle){$handle.Close()}}
    return @{Status=$status;Stage=$stage;Ms=[math]::Round($watch.Elapsed.TotalMilliseconds,1);DNSms=$dnsMs;IP=$ip;Port=$Port;HostName=$HostName;TcpAttempted=$true;ResolutionMode=if($parsedIP){'PINNED_IP'}else{'DNS_NAME'};Error=$errorDetails;DnsTransport=if($parsedIP){'NONE_PINNED_IP'}else{$dns.DnsTransport};DnsFallbackReason=if($parsedIP){$null}else{$dns.DnsFallbackReason}}
}

function Invoke-TcpFamily {
    foreach($target in $Cfg.TcpConnectTargets){
        $start=$Clock.ElapsedMilliseconds;$utc=[datetime]::UtcNow
        $result=Invoke-TcpProbe $target.HostName $target.Port $Ctx.RouteInfo.SystemDns $Cfg.DnsTimeoutMs $Cfg.TcpConnectTimeoutMs
        Publish-Probe $target 'TCP443' 'Public' $start $utc $result
        Start-Sleep -Milliseconds 50
    }
}

function Get-CurlPhaseMs {
    param([double]$FromSec,[double]$ToSec,[switch]$RequireStart)
    if($ToSec -le 0 -or $FromSec -lt 0 -or $ToSec -lt $FromSec -or ($RequireStart -and $FromSec -le 0)){return $null}
    return [math]::Round(($ToSec-$FromSec)*1000,1)
}

function Invoke-CurlTiming {
    param([string]$Url,[int]$TimeoutSec,[switch]$Doh)
    if(-not $Ctx.CurlExe){return @{Status='UNAVAILABLE';Stage='CURL_MISSING';Ms=$null}}
    $format='%{remote_ip}|%{time_namelookup}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}|%{http_code}'
    $process=[Diagnostics.Process]::new()
    $process.StartInfo=[Diagnostics.ProcessStartInfo]::new()
    $process.StartInfo.FileName=$Ctx.CurlExe
    # HEAD measures headers/TTFB without downloading full public home pages.
    # DoH endpoint sampling keeps GET because its API is not a HEAD transaction.
    $requestOptions=if($Doh){'--max-filesize 65536'}else{'--head'}
    $process.StartInfo.Arguments=($requestOptions+' '+('--silent --show-error --ipv4 --noproxy "*" --output NUL --connect-timeout {0} --max-time {0} --write-out "{1}" "{2}"' -f $TimeoutSec,$format,$Url))
    $process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true
    $process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
    $launched=$false
    try{
        [void]$process.Start();$launched=$true;$stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(($TimeoutSec+2)*1000)){$process.Kill();[void]$process.WaitForExit(1000);return @{Status='FAIL';Stage='CURL_DEADLINE';Ms=$TimeoutSec*1000}}
        $parts=$stdout.Result.Trim().Split('|');$exitCode=$process.ExitCode
        if($parts.Count -ne 7){return @{Status='UNAVAILABLE';Stage='CURL_OUTPUT_ERROR';Ms=$null;Error=$stderr.Result}}
        $dns=[double]::Parse($parts[1],[Globalization.CultureInfo]::InvariantCulture)
        $tcp=[double]::Parse($parts[2],[Globalization.CultureInfo]::InvariantCulture)
        $tls=[double]::Parse($parts[3],[Globalization.CultureInfo]::InvariantCulture)
        $ttfb=[double]::Parse($parts[4],[Globalization.CultureInfo]::InvariantCulture)
        $total=[double]::Parse($parts[5],[Globalization.CultureInfo]::InvariantCulture)
        $code=$parts[6];$ok=($exitCode -eq 0 -and $code -match '^[234][0-9][0-9]$')
        $stage=if($ok){'NONE'}elseif($exitCode -eq 6){'DNS_FAIL'}elseif($exitCode -eq 7){'TCP_FAIL'}elseif($exitCode -eq 28 -and $tcp -le 0 -and $dns -gt 0){'TCP_TIMEOUT'}elseif($exitCode -eq 28 -and $dns -le 0 -and $tcp -le 0){'DNS_OR_CONNECT_TIMEOUT'}elseif($tcp -gt 0 -and $tls -le 0){'TLS_FAIL'}elseif($tls -gt 0 -and $ttfb -le 0){'TTFB_FAIL'}elseif($exitCode -ne 0){'CURL_ERROR'}else{'HTTP_ERROR'}
        $secure=$Url.StartsWith('https://',[StringComparison]::OrdinalIgnoreCase)
        $ttfbStart=if($secure){$tls}else{$tcp}
        return @{Status=if($ok){'OK'}else{'FAIL'};Stage=$stage;Ms=[math]::Round($total*1000,1);IP=$parts[0];DNSms=if($dns -gt 0){[math]::Round($dns*1000,1)}else{$null};TCPms=(Get-CurlPhaseMs $dns $tcp);TLSms=if($secure){Get-CurlPhaseMs $tcp $tls -RequireStart}else{$null};TTFBms=(Get-CurlPhaseMs $ttfbStart $ttfb -RequireStart);TimingsSec=@{dnsLookup=$dns;connect=$tcp;tls=$tls;startTransfer=$ttfb;total=$total};HttpCode=$code;ExitCode=$exitCode;URL=$Url;HttpMethod=if($Doh){'GET'}else{'HEAD'};Measurement=if($Doh){'DOH_ENDPOINT_ONLY'}else{'HEAD_HEADERS_ONLY'}}
    }catch{return @{Status='UNAVAILABLE';Stage='CURL_RUNTIME_ERROR';Ms=$null;Error=$_.Exception.Message;URL=$Url}}finally{if($launched -and -not $process.HasExited){try{$process.Kill()}catch{}};$process.Dispose()}
}

function Invoke-HttpsFamily {
    foreach($target in $Cfg.HttpsSites){
        $start=$Clock.ElapsedMilliseconds;$utc=[datetime]::UtcNow
        Publish-Probe $target 'HTTPS' 'Public' $start $utc (Invoke-CurlTiming $target.Url $Cfg.HttpsTimeoutSec)
        Start-Sleep -Milliseconds 50
    }
}

function Invoke-DnsTransportFamily {
    foreach($target in $Ctx.TransportResolvers){
        foreach($protocol in @('DNS_UDP','DNS_TCP')){
            $start=$Clock.ElapsedMilliseconds;$utc=[datetime]::UtcNow
            $result=Invoke-DnsQuery $target.IP $QueryName $Cfg.DnsTimeoutMs -Tcp:($protocol -eq 'DNS_TCP')
            Publish-Probe $target $protocol $target.Scope $start $utc $result
        }
        $url=if($target.Name -eq 'Cloudflare'){'https://cloudflare-dns.com/dns-query?name='+[uri]::EscapeDataString($QueryName)+'&type=A'}elseif($target.Name -eq 'Google'){'https://dns.google/resolve?name='+[uri]::EscapeDataString($QueryName)+'&type=A'}else{''}
        $start=$Clock.ElapsedMilliseconds;$utc=[datetime]::UtcNow
        $doh=if($url){Invoke-CurlTiming $url 4 -Doh}else{@{Status='UNAVAILABLE';Stage='N/A';Ms=$null}}
        # Endpoint reachability/timing only, NOT a verified DoH DNS transaction.
        Publish-Probe $target 'DOH_ENDPOINT' $target.Scope $start $utc $doh
        Start-Sleep -Milliseconds 50
    }
}

function Invoke-NicFamily {
    $start=$Clock.ElapsedMilliseconds;$utc=[datetime]::UtcNow;$target=@{Name='NIC';Provider='Host'}
    try{
        $adapter=Get-NetAdapter -InterfaceIndex $Ctx.RouteInfo.InterfaceIndex -ErrorAction Stop
        $st=Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction Stop
        $route=@(Get-NetRoute -AddressFamily IPv4 -InterfaceIndex $Ctx.RouteInfo.InterfaceIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
        $up=([string]$adapter.Status -eq 'Up' -and $route.Count -gt 0)
        $routeChanged=($route.Count -gt 0 -and $Ctx.RouteInfo.Gateway -notin @($route.NextHop))
        $ranked=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Select-Object -First 32 | ForEach-Object{
            $iface=Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop
            [pscustomobject]@{Index=$_.InterfaceIndex;Gateway=$_.NextHop;Metric=([int]$_.RouteMetric+[int]$iface.InterfaceMetric)}
        })
        $winning=$ranked | Sort-Object Metric | Select-Object -First 1
        if($winning -and ($winning.Index -ne $Ctx.RouteInfo.InterfaceIndex -or $winning.Gateway -ne $Ctx.RouteInfo.Gateway)){$routeChanged=$true}
        $dnsChanged=$false
        if(-not $Cfg.SystemDnsIP){$currentDns=@((Get-DnsClientServerAddress -InterfaceIndex $Ctx.RouteInfo.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses);$dnsChanged=($currentDns.Count -gt 0 -and $currentDns[0] -ne $Ctx.RouteInfo.SystemDns)}
        $result=@{Status=if($up){'OK'}else{'FAIL'};Stage=if(-not $up){'LINK_OR_ROUTE_DOWN'}elseif($routeChanged){'ROUTE_CHANGED_RESTART_REQUIRED'}elseif($dnsChanged){'SENSOR_DNS_CHANGED_RESTART_REQUIRED'}else{'OK'};Ms=$null;Name=$adapter.Name;ObservedGateways=@($route.NextHop);ExpectedGateway=$Ctx.RouteInfo.Gateway;LinkSpeed=[string]$adapter.LinkSpeed;RxErrors=[long]$st.ReceivedPacketErrors;TxErrors=[long]$st.OutboundPacketErrors;RxDrops=[long]$st.ReceivedDiscardedPackets;TxDrops=[long]$st.OutboundDiscardedPackets;RxBytes=[long]$st.ReceivedBytes;TxBytes=[long]$st.SentBytes}
    }catch{$result=@{Status='UNAVAILABLE';Stage='NIC_COUNTERS_UNAVAILABLE';Ms=$null;Error=$_.Exception.Message}}
    Publish-Probe $target 'NIC' 'Host' $start $utc $result
}

function Invoke-TcpStatsFamily {
    $start=$Clock.ElapsedMilliseconds;$utc=[datetime]::UtcNow
    try{
        # Get-NetTCPStatistics is absent on many Windows machines. .NET maps to IP Helper.
        $st=[Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetTcpIPv4Statistics()
        $result=@{Status='OK';Stage='OK';Ms=$null;SegmentsSent=[long]$st.SegmentsSent;SegmentsReceived=[long]$st.SegmentsReceived;SegmentsRetransmitted=[long]$st.SegmentsResent;FailedConnectionAttempts=[long]$st.FailedConnectionAttempts;ResetConnections=[long]$st.ResetConnections;ErrorsReceived=[long]$st.ErrorsReceived}
    }catch{$result=@{Status='UNAVAILABLE';Stage='TCP_COUNTERS_UNAVAILABLE';Ms=$null;Error=$_.Exception.Message}}
    Publish-Probe @{Name='TCP_STACK';Provider='Host'} 'TCP_STATS' 'Host' $start $utc $result
}

function Invoke-MtuFamily {
    foreach($target in $Cfg.MtuTargets){foreach($size in $Cfg.MtuPayloadSizes){
        $start=$Clock.ElapsedMilliseconds;$utc=[datetime]::UtcNow;$ping=[Net.NetworkInformation.Ping]::new()
        $result=@{Status='FAIL';Stage='PING_ERROR';Ms=$null;IP=$target.IP;PayloadBytes=$size;DF=$true}
        try{$reply=$ping.Send($target.IP,[int]$Cfg.PingTimeoutMs,(New-Object byte[] $size),([Net.NetworkInformation.PingOptions]::new(64,$true)));$result.Stage=[string]$reply.Status;if($reply.Status -eq 'Success'){$result.Status='OK';$result.Stage='OK';$result.Ms=$reply.RoundtripTime}}catch{}finally{$ping.Dispose()}
        Publish-Probe $target 'ICMP_DF' 'Public' $start $utc $result;Start-Sleep -Milliseconds 75
    }}
}

function Get-TraceObservation {
    param([string]$Text,[string]$Destination,[bool]$Completed)
    # Only numbered hop lines count. The header may also end in the target IP.
    $hops=@($Text -split "`n" | Where-Object{$_ -match '^\s*\d+\s+.*\s(\d{1,3}(?:\.\d{1,3}){3})\s*$'} | ForEach-Object{$Matches[1]})
    $reached=$Destination -in $hops
    [pscustomobject]@{Signature=($hops -join '>');DestinationReached=$reached;Stage=if(-not $Completed){'TRACE_BUDGET'}elseif($reached){'COMPLETE'}else{'DESTINATION_UNREACHED'}}
}

function Invoke-TraceFamily {
    foreach($ip in $Cfg.TraceTargets){
        $start=$Clock.ElapsedMilliseconds;$utc=[datetime]::UtcNow;$process=[Diagnostics.Process]::new()
        $process.StartInfo=[Diagnostics.ProcessStartInfo]::new('tracert.exe',('-d -w {0} -h {1} {2}' -f $Cfg.TraceTimeoutMs,$Cfg.TraceMaxHops,$ip))
        $process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true;$process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
        $result=@{Status='UNAVAILABLE';Stage='TRACE_UNAVAILABLE';Ms=$null;IP=$ip;Text='';Signature=''}
        try{
            [void]$process.Start();$stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
            $complete=$process.WaitForExit($Cfg.TraceBudgetSec*1000)
            if(-not $complete){$process.Kill();[void]$process.WaitForExit(1000)}
            $result.Text=$stdout.Result;$result.Status=if($complete){'OK'}else{'PARTIAL'};$result.Stage=if($complete){'COMPLETE'}else{'TRACE_BUDGET'}
            $trace=Get-TraceObservation $result.Text $ip $complete
            $result.Signature=$trace.Signature;$result.DestinationReached=$trace.DestinationReached;$result.Stage=$trace.Stage
        }catch{$result.Text=$_.Exception.Message}finally{try{if(-not $process.HasExited){$process.Kill()}}catch{};$process.Dispose()}
        Publish-Probe @{Name=$ip;Provider='Route'} 'TRACE' 'Public' $start $utc $result
    }
}

function Invoke-ProbeFamily {
    switch($Family){
        ICMP {Invoke-IcmpFamily}
        DNS {Invoke-DnsFamily}
        TCP443 {Invoke-TcpFamily}
        HTTPS {Invoke-HttpsFamily}
        NIC {Invoke-NicFamily}
        TCP_STATS {Invoke-TcpStatsFamily}
        DNS_TRANSPORT {Invoke-DnsTransportFamily}
        MTU {Invoke-MtuFamily}
        TRACE {Invoke-TraceFamily}
        default {throw "Unknown probe family: $Family"}
    }
}
