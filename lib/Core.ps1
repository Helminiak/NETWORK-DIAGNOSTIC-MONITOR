# Pure classifier/state model: no Windows APIs, console access, IO, or wall-clock debounce.
function New-Assessment {
    param([string]$Code,[string]$Severity,[string]$Text,$Evidence=@(),[bool]$IncidentEligible=$false,[bool]$Corroborated=$false)
    $rows=@($Evidence)
    [pscustomobject]@{
        Code=$Code;Severity=$Severity;Text=$Text;IncidentEligible=$IncidentEligible
        Corroborated=$Corroborated;CaptureEligible=($IncidentEligible -and $Corroborated)
        Evidence=$rows;EvidenceIds=@($rows | ForEach-Object{$_.EvidenceId})
        EvidenceByStream=@{};ConfirmationClocks=@{};Families=@($rows | ForEach-Object{$_.Family} | Sort-Object -Unique)
        Protocols=@($rows | ForEach-Object{$_.Protocol} | Sort-Object -Unique)
        Providers=@($rows | Where-Object{$_.Scope -in @('Public','ExternalDNS')} | ForEach-Object{$_.Provider} | Sort-Object -Unique)
        Confidence=if($Corroborated){'CORROBORATED_SINGLE_SENSOR'}else{'OBSERVATION'}
        SharedEventCandidate=$Corroborated;SharedEventStatus='AWAITING_CENTRAL_CORRELATION'
        BadPublic=@();BadDns=@();BadHttps=@()
    }
}

function Get-EvidenceStreamKey {
    param($Row)
    # Recovery must repair the implicated transport, not mask failed TCP53 with UDP.
    $group=$Row.Protocol
    return $group+':'+$Row.Name+':'+$Row.Scope
}

function Complete-Assessment {
    param($Assessment)
    foreach($row in $Assessment.Evidence){
        $key=Get-EvidenceStreamKey $row
        if(-not $Assessment.EvidenceByStream.ContainsKey($key) -or $row.EndMonoMs -gt $Assessment.EvidenceByStream[$key]){$Assessment.EvidenceByStream[$key]=[long]$row.EndMonoMs}
        $protocolGroup=switch($row.Protocol){DNS_UDP{'DNS'}DNS_TCP{'DNS'}default{$row.Protocol}}
        # Successes must not advance the failure clock. A lone failed proxy
        # query plus newer direct successes previously confirmed an incident.
        $role=if($Assessment.Code -eq 'DNS_ANSWER_REDIRECTION'){'ANSWER_ANOMALY'}else{$row.Status}
        $group=$protocolGroup+':'+$role
        if(-not $Assessment.ConfirmationClocks.ContainsKey($group) -or $row.EndMonoMs -lt $Assessment.ConfirmationClocks[$group]){$Assessment.ConfirmationClocks[$group]=[long]$row.EndMonoMs}
    }
    return $Assessment
}

function Get-CoreAssessment {
    param($Rows,[long]$NowMs,$Config)
    $fresh=@($Rows | Where-Object{ $_.StartMonoMs -ge $Config.EvidenceEpochMs -and $_.Status -in @('OK','FAIL') -and $NowMs-$_.EndMonoMs -le $Config.EvidenceWindowSec*1000 -and $NowMs -ge $_.EndMonoMs })
    # Select freshest resolver result across UDP/TCP; a current success supersedes an old failure.
    $dnsLatest=@($fresh | Where-Object{$_.Protocol -in @('DNS_UDP','DNS_TCP')} | Group-Object { $_.Name+':'+$_.Scope } | ForEach-Object{$_.Group | Sort-Object EndMonoMs -Descending | Select-Object -First 1})
    $failed=@($fresh | Where-Object{$_.Status -eq 'FAIL' -and $_.Protocol -notin @('DNS_UDP','DNS_TCP')})+@($dnsLatest | Where-Object{$_.Status -eq 'FAIL' -and $_.Stage -notin @('TRUNCATED','NXDOMAIN','NO_A_ANSWER','REFUSED')})
    if($failed.Count -gt 0){
        $newest=($failed | Measure-Object EndMonoMs -Maximum).Maximum
        $failed=@($failed | Where-Object{$newest-$_.EndMonoMs -le $Config.CorrelationWindowSec*1000})
        $fresh=@($fresh | Where-Object{$newest-$_.EndMonoMs -le $Config.CorrelationWindowSec*1000})
        $dnsLatest=@($dnsLatest | Where-Object{$newest-$_.EndMonoMs -le $Config.CorrelationWindowSec*1000})
    }
    $gw=$fresh | Where-Object{$_.Protocol -eq 'ICMP' -and $_.Scope -eq 'Gateway'} | Sort-Object EndMonoMs -Descending | Select-Object -First 1
    $gwBad=@($failed | Where-Object{$_.Protocol -eq 'ICMP' -and $_.Scope -eq 'Gateway'})
    $bgwBad=@($failed | Where-Object{$_.Protocol -eq 'ICMP' -and $_.Scope -eq 'Gateway2'})
    $publicPing=@($failed | Where-Object{$_.Protocol -eq 'ICMP' -and $_.Scope -eq 'Public'})
    $externalDns=@($failed | Where-Object{$_.Protocol -in @('DNS_UDP','DNS_TCP') -and $_.Scope -eq 'ExternalDNS' -and $_.Stage -in @('DNS_TIMEOUT','DNS_SOCKET_ERROR','DNS_TCP_CONNECT_TIMEOUT')})
    # DNS_FAIL / DNS_TIMEOUT are NEVER TCP transport evidence.
    $tcp=@($failed | Where-Object{(-not $_.Data.IP -or (Test-PublicProbeAddress $_.Data.IP)) -and $_.Protocol -eq 'TCP443' -and $_.Stage -in @('TCP_TIMEOUT','TCP_ERROR') -and $_.Data.TcpAttempted})
    # Microsoft-only failures, TLS, server responses and TTFB are not WAN transport evidence.
    $https=@($failed | Where-Object{$_.Protocol -eq 'HTTPS' -and (-not $_.Data.IP -or (Test-PublicProbeAddress $_.Data.IP)) -and $_.Stage -in @('TCP_FAIL','TCP_TIMEOUT')})
    $hostRows=@($failed | Where-Object{$_.Protocol -eq 'NIC' -and $_.Stage -eq 'LINK_OR_ROUTE_DOWN'})
    $hostErrors=@($fresh | Where-Object{$_.Protocol -eq 'NIC' -and ($_.Data.dRxErrors -gt 0 -or $_.Data.dTxErrors -gt 0)})
    $pingWide=@($publicPing.Provider | Sort-Object -Unique).Count -ge 2
    $dnsWide=@($externalDns.Provider | Sort-Object -Unique).Count -ge 2
    $tcpWide=@($tcp.Provider | Sort-Object -Unique).Count -ge 2
    $httpsWide=@($https.Provider | Sort-Object -Unique).Count -ge 2
    $remote=@();$groups=0
    if($pingWide){$remote+= $publicPing;$groups++}
    if($dnsWide){$remote+= $externalDns;$groups++}
    if($tcpWide){$remote+= $tcp;$groups++}
    if($httpsWide){$remote+= $https;$groups++}
    $anomalies=@($fresh | Where-Object{Test-ObservationAnswerAnomaly $_ $Config})
    $badAnswers=@($anomalies | Where-Object{$_.Protocol -in @('DNS_UDP','DNS_TCP')})
    $redirection=(@($badAnswers.Provider | Sort-Object -Unique).Count -ge 2 -and @($badAnswers.Data.QueryName | Sort-Object -Unique).Count -ge 2)
    $answerEvidence=@($badAnswers | Group-Object {Get-EvidenceStreamKey $_} | ForEach-Object{$_.Group | Sort-Object EndMonoMs -Descending | Select-Object -First 1})
    $tcp53Bad=@($fresh | Where-Object{$_.Protocol -eq 'DNS_TCP' -and $_.Status -eq 'FAIL' -and $_.Stage -in @('DNS_TCP_CONNECT_TIMEOUT','DNS_TIMEOUT','DNS_SOCKET_ERROR')})
    $udpGood=@($fresh | Where-Object{$_.Protocol -eq 'DNS_UDP' -and (Test-ObservationUsableSuccess $_ $Config)})
    $selective53=@($tcp53Bad | Where-Object{ $_.Name -in @($udpGood.Name) })
    $routeChanges=@($fresh | Where-Object{$_.Protocol -eq 'NIC' -and $_.Stage -in @('ROUTE_CHANGED_RESTART_REQUIRED','SENSOR_DNS_CHANGED_RESTART_REQUIRED')})
    $a=$null
    if(($hostRows.Count -gt 0 -or $hostErrors.Count -gt 0) -and ($gwBad.Count -gt 0 -or $tcpWide -or $dnsWide)){
        $a=New-Assessment 'HOST_LOCAL_PATH' 'CRITICAL' 'Host link/route or NIC errors coincide with failed reachability; inspect this sensor and its Ethernet path.' (@($hostRows)+@($hostErrors)+@($gwBad)+@($remote)) $true $true
    }elseif($gwBad.Count -gt 0 -and ($tcpWide -or $dnsWide -or $httpsWide)){
        $code=if($Config.SENSOR_ROLE -eq 'DIRECT_BGW'){'HOST_LOCAL_PATH'}else{'ROUTER_LAN'}
        $a=New-Assessment $code 'CRITICAL' 'Default-gateway path and non-ICMP probes fail together; single-sensor evidence cannot separate host, cable, switch and gateway.' (@($gwBad)+@($remote)) $true $true
    }elseif($Config.SENSOR_ROLE -eq 'BEHIND_ASUS' -and $gw -and $gw.Status -eq 'OK' -and $bgwBad.Count -gt 0 -and ($tcpWide -or $dnsWide -or $httpsWide)){
        $a=New-Assessment 'BGW_WAN_EDGE' 'CRITICAL' 'ASUS-side gateway responds while the BGW path and external protocols fail; boundary is ASUS WAN through BGW/upstream, device ownership remains unproven.' (@($gw)+@($bgwBad)+@($remote)) $true $true
    }elseif($routeChanges.Count){
        $a=New-Assessment 'SENSOR_ROUTE_CHANGED' 'WARNING' 'Effective default route or selected DNS configuration changed. Restart the sensor to refresh topology; probes are not bound to a physical interface, so WAN ownership is unproven.' $routeChanges
    }elseif($redirection){
        $a=New-Assessment 'DNS_ANSWER_REDIRECTION' 'CRITICAL' 'Multiple public names return nonpublic addresses through multiple resolvers. Interception, captive portal or deliberate filtering is possible; source device and WAN availability are unproven.' $answerEvidence $true $true
    }elseif($gw -and $gw.Status -eq 'OK' -and $anomalies.Count -eq 0 -and $groups -ge 2 -and ($tcpWide -or $httpsWide -or ($pingWide -and $dnsWide))){
        $a=New-Assessment 'UPSTREAM_WAN_CONFIRMED' 'CRITICAL' 'Independent protocols fail across multiple providers while the local gateway responds; compare a DIRECT_BGW sensor before assigning ownership.' (@($gw)+@($remote)) $true $true
    }else{
        $proxy=@($fresh | Where-Object{$_.Protocol -in @('DNS_UDP','DNS_TCP') -and $_.Scope -in @('RouterDNS','BgwDNS')} |
            Group-Object {Get-EvidenceStreamKey $_} | ForEach-Object{$_.Group | Sort-Object EndMonoMs -Descending | Select-Object -First 1} |
            Where-Object{$_.Status -eq 'FAIL' -and $_.Stage -notin @('TRUNCATED','NXDOMAIN','NO_A_ANSWER','REFUSED')})
        $dnsGood=@($fresh | Where-Object{(Test-ObservationUsableSuccess $_ $Config) -and $_.Scope -eq 'ExternalDNS' -and $_.Protocol -in @('DNS_UDP','DNS_TCP')})
        if($proxy.Count -gt 0 -and @($dnsGood.Provider | Sort-Object -Unique).Count -ge 2){
            $p=$proxy | Sort-Object EndMonoMs -Descending | Select-Object -First 1
            $good=@($dnsGood | Where-Object{
                $p.Data.QueryName -and $_.Data.QueryName -eq $p.Data.QueryName -and $_.Protocol -eq $p.Protocol -and
                [math]::Abs($_.EndMonoMs-$p.EndMonoMs) -le $Config.CorrelationWindowSec*1000
            } | Group-Object Name | ForEach-Object{$_.Group | Sort-Object EndMonoMs -Descending | Select-Object -First 1})
            if(@($good.Provider | Sort-Object -Unique).Count -ge 2){
                $code=if($p.Scope -eq 'BgwDNS'){'BGW_DNS_PROXY'}else{'ROUTER_DNS_PROXY'}
                $a=New-Assessment $code 'WARNING' 'Proxy DNS query fails while independent direct resolvers answer the same name over the same transport. Repeated failure evidence is required for confirmation; WAN availability and device ownership remain separate.' (@($p)+@($good)) $true $true
            }
        }
        if(-not $a){
            if($anomalies.Count){$a=New-Assessment 'DNS_INTEGRITY_WATCH' 'WATCH' 'Public-name answer contains a nonpublic address; awaiting multiple names and resolvers. Public IP controls remain separate.' $anomalies}
            elseif(@($selective53.Provider | Sort-Object -Unique).Count -ge 2){$a=New-Assessment 'DNS_TCP_PATH_WATCH' 'WATCH' 'TCP53 fails through multiple resolvers while UDP answers arrive; this is a selective transport observation.' $selective53}
            elseif($pingWide -or $gwBad.Count -gt 0 -or $bgwBad.Count -gt 0){$a=New-Assessment 'ICMP_ONLY_WATCH' 'WATCH' 'ICMP loss without independent protocol corroboration; no formal WAN incident or packet capture.' (@($publicPing)+@($gwBad)+@($bgwBad))}
            elseif($tcpWide){$a=New-Assessment 'TCP443_WATCH' 'WATCH' 'Multiple providers fail TCP connect, but independent protocol corroboration is absent.' $tcp}
            elseif($dnsWide){$a=New-Assessment 'DNS_PATH_WATCH' 'WATCH' 'Direct resolvers fail; awaiting independent protocol evidence before classifying a network incident.' $externalDns}
            elseif($failed.Count -gt 0){$a=New-Assessment 'PROVIDER_OR_HOST_WATCH' 'WATCH' 'Isolated provider, application, DNS or host observations; see watchlist and raw evidence.' $failed}
            elseif($fresh.Count -eq 0){$a=New-Assessment 'WAITING_FOR_EVIDENCE' 'WATCH' 'No fresh usable observations; missing or stale data is not recovery.'}
            else{$a=New-Assessment 'HEALTHY' 'OK' 'No corroborated fault in fresh observations.' $fresh}
        }
    }
    return Complete-Assessment $a
}

function New-IncidentState {
    return [pscustomobject]@{Candidate=$null;FirstMs=0L;FirstStreams=@{};LastStreams=@{};Active=$null;ActiveStreams=@{};ConfirmedMs=0L;RecoveryFirstMs=$null;RecoveryStreams=@{};EpisodeId=''}
}

function Test-AllStreamsAdvanced {
    param($Current,$Previous)
    if($Previous.Count -eq 0){return $false}
    foreach($key in $Previous.Keys){if(-not $Current.ContainsKey($key) -or $Current[$key] -le $Previous[$key]){return $false}}
    return $true
}

function Update-IncidentState {
    param($State,$Assessment,$Latest,[long]$NowMs,$Config)
    $actions=New-Object System.Collections.ArrayList
    if($Assessment.IncidentEligible){
        $State.RecoveryFirstMs=$null;$State.RecoveryStreams=@{}
        if($State.Candidate -ne $Assessment.Code){
            $State.Candidate=$Assessment.Code;$State.FirstMs=$NowMs
            $State.FirstStreams=@{}+$Assessment.ConfirmationClocks;$State.LastStreams=@{}+$Assessment.ConfirmationClocks
            if($Assessment.CaptureEligible -and $State.Active -ne $Assessment.Code){[void]$actions.Add('PRETRIGGER')}
        }else{$State.LastStreams=@{}+$Assessment.ConfirmationClocks}
        # The oldest evidence in each contributing protocol AND outcome group must advance;
        # changing failed target membership does not require an identical target set.
        # A new ping alongside stale DNS/TCP still cannot confirm the candidate.
        if($NowMs-$State.FirstMs -ge $Config.EventDebounceSec*1000 -and (Test-AllStreamsAdvanced $State.LastStreams $State.FirstStreams) -and $State.Active -ne $Assessment.Code){
            if($State.Active){[void]$actions.Add('RECLASSIFY')}
            $State.Active=$Assessment.Code;$State.ActiveStreams=@{}+$Assessment.EvidenceByStream
            $State.ConfirmedMs=$NowMs;$State.EpisodeId=[guid]::NewGuid().ToString('N')
            [void]$actions.Add('INCIDENT')
        }
    }else{
        $State.Candidate=$null;$State.FirstStreams=@{};$State.LastStreams=@{}
        if($State.Active){
            $success=@{};$healthy=$true
            foreach($key in $State.ActiveStreams.Keys){
                $matches=@($Latest | Where-Object{(Get-EvidenceStreamKey $_) -eq $key} | Sort-Object EndMonoMs -Descending)
                $row=$matches | Select-Object -First 1
                if(-not $row -or (-not (Test-ObservationUsableSuccess $row $Config)) -or $row.StartMonoMs -lt $Config.EvidenceEpochMs -or $row.EndMonoMs -le $State.ActiveStreams[$key] -or $NowMs-$row.EndMonoMs -gt $Config.EvidenceWindowSec*1000){$healthy=$false;break}
                $success[$key]=[long]$row.EndMonoMs
            }
            if($healthy){
                if($null -eq $State.RecoveryFirstMs){$State.RecoveryFirstMs=$NowMs;$State.RecoveryStreams=$success}
                if($NowMs-$State.RecoveryFirstMs -ge $Config.RecoveryHoldSec*1000 -and (Test-AllStreamsAdvanced $success $State.RecoveryStreams)){
                    [void]$actions.Add('RECOVERY');$State.Active=$null;$State.ActiveStreams=@{};$State.RecoveryFirstMs=$null
                }
            }else{$State.RecoveryFirstMs=$null;$State.RecoveryStreams=@{}}
        }
    }
    return @($actions)
}

function Get-MonitorHealth {
    param($Assessment,$State,$Scheduler,[long]$NowMs,$Config)
    $network=if($State.Active){$State.Active}elseif($Assessment.IncidentEligible){'PENDING_CORROBORATED_FAULT'}elseif($Assessment.Code -eq 'WAITING_FOR_EVIDENCE'){'UNKNOWN'}else{'NO_CORROBORATED_FAULT'}
    $probe='OK';$pending=$false
    foreach($job in $Scheduler.Jobs.Values){
        if(-not $job.Enabled){continue}
        if($job.Completed -eq 0){$pending=$true}
        if($NowMs -gt $job.NextMs+$job.BudgetMs -or ($job.Handle -and $NowMs-$job.StartedMs -gt $job.BudgetMs)){$probe='STALLED'}
        if(-not $job.Handle -and $job.Completed -gt 0 -and $NowMs-$job.LastCompletedMs -gt $job.IntervalMs+$job.BudgetMs){$probe='STALE'}
    }
    if($probe -eq 'OK' -and $pending){$probe='STARTING'}
    [pscustomobject]@{Network=$network;Probes=$probe}
}
